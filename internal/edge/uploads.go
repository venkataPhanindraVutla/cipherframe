package edge

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

// partIOTimeout bounds one part upload end to end. It overrides the listener's short default
// read and write deadlines for this request only (a 64 MiB part on a slow link takes minutes).
const partIOTimeout = 15 * time.Minute

// Uploads are the collaborators of the upload endpoints (ADR 0025). Without Authz the endpoints
// answer 503 dependency_unavailable, so the routes exist in every process.
type Uploads struct {
	// Authz checks upload tokens against the database.
	Authz *uploads.Authorizer
	// Parts receives multipart parts.
	Parts *uploads.Receiver
	// Tus is the data store behind the mounted tus handler, and Locker serialises it across
	// replicas. Both are needed for tus; without them the tus mount answers 503.
	Tus    *uploads.TusStore
	Locker *uploads.Locker
	// Limits are the upload limits, for tusd's own checks.
	Limits uploads.Limits
	// PublicURL is the base URL clients reach this listener at, for tus Location headers. Empty
	// derives it from the request.
	PublicURL string
}

func errUnavailable() error {
	return errs.New(errs.DependencyUnavailable, "Uploads are not available.")
}

// authorize checks the upload token of r. Every failure is the same unauthenticated answer
// (see uploads.Authorizer); a database failure is returned as its own error.
func (u *Uploads) authorize(r *http.Request) (uploads.Grant, error) {
	hdr := r.Header.Values("Authorization")
	if len(hdr) != 1 {
		return uploads.Grant{}, errs.New(errs.Unauthenticated, "The upload token is missing, invalid or expired.")
	}
	token, ok := auth.BearerToken(hdr[0])
	if !ok {
		return uploads.Grant{}, errs.New(errs.Unauthenticated, "The upload token is missing, invalid or expired.")
	}
	if _, err := uploads.HashToken(token); err != nil { // not even shaped like an upload token (an API key, say)
		return uploads.Grant{}, errs.New(errs.Unauthenticated, "The upload token is missing, invalid or expired.")
	}
	if u == nil || u.Authz == nil {
		return uploads.Grant{}, errUnavailable()
	}
	return u.Authz.Authorize(r.Context(), token)
}

// writeAuthError answers an authorization failure, with WWW-Authenticate on a 401.
func writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	var e *errs.Error
	if errors.As(err, &e) && e.Code == errs.Unauthenticated {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	httpx.ResponseErrorHandler(w, r, err)
}

type contentLengthKey struct{}

// guarded wraps the generated server interface: the upload operations authenticate with the
// upload token before their handler (or body decoding) runs. Health and readiness pass through.
type guarded struct {
	gen.ServerInterface
	up   *Uploads
	play *Playback
}

func (g guarded) run(w http.ResponseWriter, r *http.Request, next func(*http.Request)) {
	grant, err := g.up.authorize(r)
	if err != nil {
		writeAuthError(w, r, err)
		return
	}
	next(r.WithContext(uploads.WithGrant(r.Context(), grant)))
}

func (g guarded) ListUploadParts(w http.ResponseWriter, r *http.Request, assetID gen.AssetId) {
	g.run(w, r, func(r *http.Request) { g.ServerInterface.ListUploadParts(w, r, assetID) })
}

func (g guarded) PutUploadPart(w http.ResponseWriter, r *http.Request, assetID gen.AssetId, partNumber int) {
	g.run(w, r, func(r *http.Request) {
		// The part may take long to arrive: replace the listener's short deadlines for this
		// request, and cap the body at the part size so a client cannot stream without end.
		rc := http.NewResponseController(w)
		deadline := time.Now().Add(partIOTimeout)
		_ = rc.SetReadDeadline(deadline)
		_ = rc.SetWriteDeadline(deadline.Add(30 * time.Second))
		if g.up.Parts != nil && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, g.up.Parts.PartBytes())
		}
		ctx := context.WithValue(r.Context(), contentLengthKey{}, r.ContentLength)
		g.ServerInterface.PutUploadPart(w, r.WithContext(ctx), assetID, partNumber)
	})
}

func (s *server) parts() (*uploads.Receiver, error) {
	if s.up == nil || s.up.Parts == nil {
		return nil, errUnavailable()
	}
	return s.up.Parts, nil
}

func pathAsset(s string) (id.AssetID, error) {
	a, err := id.Parse[id.AssetKind](s)
	if err != nil {
		return id.AssetID{}, errs.New(errs.NotFound, "No such upload.")
	}
	return a, nil
}

func grantFrom(ctx context.Context) (uploads.Grant, error) {
	g, ok := uploads.GrantFrom(ctx)
	if !ok { // the guard always sets it; fail closed
		return uploads.Grant{}, errs.New(errs.Unauthenticated, "The upload token is missing, invalid or expired.")
	}
	return g, nil
}

// ListUploadParts lists the parts received so far.
func (s *server) ListUploadParts(ctx context.Context, req gen.ListUploadPartsRequestObject) (gen.ListUploadPartsResponseObject, error) {
	g, err := grantFrom(ctx)
	if err != nil {
		return nil, err
	}
	rcv, err := s.parts()
	if err != nil {
		return nil, err
	}
	aid, err := pathAsset(req.AssetId)
	if err != nil {
		return nil, err
	}
	parts, err := rcv.List(ctx, g, aid)
	if err != nil {
		return nil, err
	}
	body := gen.UploadPartList{PartSizeBytes: rcv.PartBytes(), Items: make([]gen.UploadPart, len(parts))}
	for i, p := range parts {
		body.Items[i] = gen.UploadPart{PartNumber: p.Number, SizeBytes: p.SizeBytes, Etag: p.ETag}
	}
	return gen.ListUploadParts200JSONResponse{Body: body, Headers: gen.ListUploadParts200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// PutUploadPart streams one part to the object store.
func (s *server) PutUploadPart(ctx context.Context, req gen.PutUploadPartRequestObject) (gen.PutUploadPartResponseObject, error) {
	g, err := grantFrom(ctx)
	if err != nil {
		return nil, err
	}
	rcv, err := s.parts()
	if err != nil {
		return nil, err
	}
	aid, err := pathAsset(req.AssetId)
	if err != nil {
		return nil, err
	}
	size, _ := ctx.Value(contentLengthKey{}).(int64)
	if size < 1 {
		return nil, errs.New(errs.InvalidRequest, "A Content-Length header with the size of the part is required.")
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	p, err := rcv.Put(ctx, g, aid, req.PartNumber, req.Body, size)
	if err != nil {
		return nil, err
	}
	return gen.PutUploadPart200JSONResponse{
		Body:    gen.UploadPart{PartNumber: p.Number, SizeBytes: p.SizeBytes, Etag: p.ETag},
		Headers: gen.PutUploadPart200ResponseHeaders{XRequestId: requestID(ctx)},
	}, nil
}
