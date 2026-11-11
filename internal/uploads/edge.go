package uploads

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
)

// errBadToken is the one answer for every token problem: malformed, unknown, expired, or bound to
// an asset that no longer accepts bytes. It does not say which.
func errBadToken() error {
	return errs.New(errs.Unauthenticated, "The upload token is missing, invalid or expired.")
}

// Grant is what a valid upload token allows: sending bytes for one asset. The asset snapshot is
// read when the token was checked; its SourceKey and S3UploadID never leave this process.
type Grant struct {
	Asset db.Asset
}

type grantKey struct{}

// WithGrant returns a context carrying g. Edge sets it after checking the token; the tus data store
// and the part receiver read it.
func WithGrant(ctx context.Context, g Grant) context.Context { return context.WithValue(ctx, grantKey{}, g) }

// GrantFrom returns the grant stored by WithGrant.
func GrantFrom(ctx context.Context) (Grant, bool) {
	g, ok := ctx.Value(grantKey{}).(Grant)
	return g, ok
}

// Authorizer checks upload tokens statefully: every request looks the token up in the database,
// so an expired token, a committed or aborted asset, and a deleted token all stop working at once.
type Authorizer struct {
	repos *db.Repos
	now   func() time.Time
}

// NewAuthorizer returns an Authorizer. now defaults to time.Now.
func NewAuthorizer(repos *db.Repos, now func() time.Time) *Authorizer {
	if now == nil {
		now = time.Now
	}
	return &Authorizer{repos: repos, now: now}
}

// Authorize returns the grant for a presented token, or an unauthenticated error. A database
// failure is returned as its own (retryable) error, never as a token verdict.
func (a *Authorizer) Authorize(ctx context.Context, presented string) (Grant, error) {
	hash, err := HashToken(presented)
	if err != nil {
		return Grant{}, errBadToken()
	}
	g, err := a.repos.GetUploadGrant(ctx, hash)
	if err != nil {
		var e *errs.Error
		if errors.As(err, &e) && e.Code == errs.NotFound {
			return Grant{}, errBadToken()
		}
		return Grant{}, err
	}
	now := a.now()
	switch {
	case !now.Before(g.TokenExpiresAt):
		return Grant{}, errBadToken()
	case g.Asset.UploadExpiresAt != nil && !now.Before(*g.Asset.UploadExpiresAt):
		return Grant{}, errBadToken()
	case !g.Asset.State.Accepting():
		return Grant{}, errBadToken()
	}
	return Grant{Asset: g.Asset}, nil
}

// Part is a received part as clients see it.
type Part struct {
	Number    int
	SizeBytes int64
	ETag      string
}

// Receiver stores multipart parts that clients send to the edge. Bytes stream from the request to
// the object store (storage.Store.UploadPart); nothing is buffered beyond what the SDK needs.
type Receiver struct {
	repos  *db.Repos
	source storage.Store
	limits Limits
	now    func() time.Time
}

// NewReceiver returns a Receiver. now defaults to time.Now.
func NewReceiver(repos *db.Repos, source storage.Store, limits Limits, now func() time.Time) *Receiver {
	if now == nil {
		now = time.Now
	}
	return &Receiver{repos: repos, source: source, limits: limits, now: now}
}

// requireMultipart rejects a grant for an asset that is not a multipart upload, and a path asset
// that is not the grant's asset (reported as not_found, so a token cannot probe other assets).
func requireMultipart(g Grant, pathAsset id.AssetID) error {
	if g.Asset.ID != pathAsset {
		return errs.New(errs.NotFound, "No such upload.")
	}
	if g.Asset.UploadMethod != db.UploadMultipart {
		return errs.New(errs.Conflict, "This asset is uploaded with tus, not in parts.")
	}
	return nil
}

// Put streams one part of size bytes (the request's Content-Length) from body to the object store
// and records it. Sending a part again replaces it. The caller passes a body already capped at
// size bytes.
func (r *Receiver) Put(ctx context.Context, g Grant, pathAsset id.AssetID, n int, body io.Reader, size int64) (Part, error) {
	if err := requireMultipart(g, pathAsset); err != nil {
		return Part{}, err
	}
	if err := CheckPartNumber(n); err != nil {
		return Part{}, err
	}
	a := g.Asset
	other, err := r.repos.SumOtherUploadPartSizes(ctx, a.ID, n)
	if err != nil {
		return Part{}, err
	}
	if err := r.limits.CheckPart(size, a.SizeBytes, other); err != nil {
		return Part{}, err
	}
	if a.State == db.AssetCreated { // the first part starts the upload; losing the race is fine
		_, err := r.repos.TransitionAsset(ctx, a.TenantID, a.ID, db.Transition{
			From: db.AssetCreated, To: db.AssetUploading, At: r.now().UTC(),
		})
		if err != nil && !errors.Is(err, db.ErrStateChanged) {
			return Part{}, err
		}
	}
	etag, err := r.source.UploadPart(ctx, a.SourceKey, a.S3UploadID, int32(n), body, size) //nolint:gosec // 1..10000
	if err != nil {
		return Part{}, uploadError(err)
	}
	if err := r.repos.RecordUploadPart(ctx, a.ID, db.UploadPart{PartNumber: n, ETag: etag, SizeBytes: size}); err != nil {
		return Part{}, err
	}
	return Part{Number: n, SizeBytes: size, ETag: etag}, nil
}

// List returns the parts received so far, in ascending order, so a client can resume.
func (r *Receiver) List(ctx context.Context, g Grant, pathAsset id.AssetID) ([]Part, error) {
	if err := requireMultipart(g, pathAsset); err != nil {
		return nil, err
	}
	rows, err := r.repos.ListUploadParts(ctx, g.Asset.ID)
	if err != nil {
		return nil, err
	}
	out := make([]Part, len(rows))
	for i, p := range rows {
		out[i] = Part{Number: p.PartNumber, SizeBytes: p.SizeBytes, ETag: p.ETag}
	}
	return out, nil
}

// PartBytes is the part size clients are told to use.
func (r *Receiver) PartBytes() int64 { return r.limits.PartBytes }

// uploadError maps a storage failure while streaming a part. A body that ended early or a
// connection that dropped is the client's problem, not an outage.
func uploadError(err error) error {
	switch storage.KindOf(err) {
	case storage.Invalid:
		return errs.Wrap(errs.InvalidRequest, "The part could not be stored; check its size and number.", err)
	case storage.NotFound:
		return errs.Wrap(errs.Conflict, "The upload is no longer open.", err)
	}
	return storage.ToAppError(err)
}
