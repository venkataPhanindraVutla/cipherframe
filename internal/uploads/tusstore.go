package uploads

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tus/tusd/v2/pkg/handler"
	"github.com/tus/tusd/v2/pkg/s3store"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// TusStore is the tusd data store of the edge role. It wraps tusd's S3 store so that
//
//   - the upload object, its ".info" object and its ".part" object all live under the asset's
//     source prefix: the store's object prefix is empty and the pre-create hook sets the tusd
//     upload ID to the asset's random source key, so tusd builds every key from it;
//   - the upload is addressed by the asset ID everywhere clients can see (the Location header,
//     the URL of HEAD and PATCH), never by the object key or the object store's upload ID;
//   - at most one upload ever starts per asset, serialised by a row lock and a compare-and-set
//     (created -> uploading);
//   - client-supplied metadata (file names included) is dropped, and nothing is ever read back
//     through tus;
//   - every error is sanitised before tusd can put it in a response or log.
type TusStore struct {
	inner  s3store.S3Store
	pool   *pgxpool.Pool
	repos  *db.Repos
	limits Limits
	now    func() time.Time
}

// Tus buffering. tusd parks incoming data on local disk until a part is complete, so one active
// upload needs up to (tusMaxBufferedParts+1) x the part size of temporary space.
const (
	tusMaxBufferedParts   = 2
	tusConcurrentPartPuts = 4
)

// TusDeps are the collaborators of a TusStore.
type TusDeps struct {
	Pool   *pgxpool.Pool
	S3     s3store.S3API // the internal S3 client
	Bucket string        // the source bucket
	Limits Limits
	Now    func() time.Time
	// TempDir is where tusd parks parts until they are complete; empty means the OS default.
	TempDir string
}

// NewTusStore builds the store.
func NewTusStore(d TusDeps) (*TusStore, error) {
	if d.Pool == nil || d.S3 == nil || d.Bucket == "" {
		return nil, errors.New("uploads: a pool, an S3 client and the source bucket are required")
	}
	if err := d.Limits.Validate(); err != nil {
		return nil, err
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	inner := s3store.New(d.Bucket, d.S3)
	inner.ObjectPrefix = "" // keys are the asset's source key, which already carries its prefix
	inner.MetadataObjectPrefix = ""
	inner.MinPartSize = MinPartBytes
	inner.PreferredPartSize = d.Limits.PartBytes
	inner.MaxPartSize = max(d.Limits.PartBytes, MinPartBytes+1)
	inner.MaxObjectSize = d.Limits.MaxSourceBytes
	inner.MaxBufferedParts = tusMaxBufferedParts
	inner.TemporaryDirectory = d.TempDir
	inner.SetConcurrentPartUploads(tusConcurrentPartPuts)
	return &TusStore{inner: inner, pool: d.Pool, repos: db.New(d.Pool), limits: d.Limits, now: d.Now}, nil
}

// UseIn registers the store as the core of a tusd composer. Only the core is used: no
// termination (aborting goes through the API), no concatenation, no deferred length, and no
// content serving (the source is never read back through edge).
func (s *TusStore) UseIn(c *handler.StoreComposer) { c.UseCore(s) }

var _ handler.DataStore = (*TusStore)(nil)

// Tus protocol errors. They are fixed texts: nothing of the object store or the asset's key.
var (
	errTusNoGrant   = handler.NewError("ERR_UPLOAD_UNAUTHORIZED", "the upload token is missing, invalid or expired", http.StatusUnauthorized)
	errTusWrongType = handler.NewError("ERR_UPLOAD_METHOD", "this asset is uploaded in parts, not with tus", http.StatusConflict)
	errTusStarted   = handler.NewError("ERR_UPLOAD_EXISTS", "an upload was already started for this asset", http.StatusConflict)
	errTusSize      = handler.NewError("ERR_UPLOAD_SIZE", "Upload-Length must equal the size declared when the asset was created", http.StatusBadRequest)
	errTusInternal  = handler.NewError("ERR_INTERNAL_SERVER_ERROR", "internal error", http.StatusInternalServerError)
	errTusNoRead    = handler.NewError("ERR_FORBIDDEN", "uploads cannot be read back", http.StatusForbidden)
)

// PreCreate is tusd's PreUploadCreateCallback. It checks the grant, the declared size and the
// state, and sets the tusd upload ID to the asset's source key so tusd stores the upload object
// and its ".info" object under the asset's source prefix.
func (s *TusStore) PreCreate(hook handler.HookEvent) (handler.HTTPResponse, handler.FileInfoChanges, error) {
	g, ok := GrantFrom(hook.Context)
	if !ok {
		return handler.HTTPResponse{}, handler.FileInfoChanges{}, errTusNoGrant
	}
	a := g.Asset
	switch {
	case a.UploadMethod != db.UploadTus:
		return handler.HTTPResponse{}, handler.FileInfoChanges{}, errTusWrongType
	case a.State != db.AssetCreated || a.S3UploadID != "":
		return handler.HTTPResponse{}, handler.FileInfoChanges{}, errTusStarted
	case hook.Upload.SizeIsDeferred || hook.Upload.Size != a.SizeBytes || a.SizeBytes > s.limits.MaxSourceBytes:
		return handler.HTTPResponse{}, handler.FileInfoChanges{}, errTusSize
	}
	changes := handler.FileInfoChanges{ID: a.SourceKey, MetaData: sourceMetadata(a), Storage: map[string]string{}}
	return handler.HTTPResponse{}, changes, nil
}

// sourceMetadata is all the metadata an upload keeps: the asset's content type, if any. File
// names and every other client-supplied value are dropped (ADR 0040).
func sourceMetadata(a db.Asset) handler.MetaData {
	m := handler.MetaData{}
	if a.ContentType != "" {
		m["filetype"] = a.ContentType
	}
	return m
}

// NewUpload starts the upload for the grant's asset: under a row lock it creates tusd's S3
// multipart upload and ".info" object, records the multipart upload ID and moves the asset
// created -> uploading. A second attempt finds the asset no longer in created and is refused.
func (s *TusStore) NewUpload(ctx context.Context, info handler.FileInfo) (handler.Upload, error) {
	g, ok := GrantFrom(ctx)
	if !ok {
		return nil, errTusNoGrant
	}
	a := g.Asset
	if info.ID != a.SourceKey || info.Size != a.SizeBytes { // PreCreate guarantees both
		return nil, errTusInternal
	}
	info.MetaData = sourceMetadata(a)
	info.Storage = nil

	var created handler.Upload
	err := db.Tx(ctx, s.pool, func(r *db.Repos) error {
		cur, err := r.LockAsset(ctx, a.TenantID, a.ID) // serialises concurrent creations
		if err != nil {
			return err
		}
		if cur.State != db.AssetCreated || cur.S3UploadID != "" || cur.SourceKey != a.SourceKey {
			return errTusStarted
		}
		if created, err = s.inner.NewUpload(ctx, info); err != nil {
			created = nil
			return s.fail(ctx, "tus_create", err)
		}
		innerInfo, err := created.GetInfo(ctx)
		if err != nil {
			return s.fail(ctx, "tus_create", err)
		}
		mp, ok := strings.CutPrefix(innerInfo.ID, a.SourceKey+"+")
		if !ok || mp == "" {
			return errTusInternal
		}
		_, err = r.StartTusUpload(ctx, a.TenantID, a.ID, mp, s.now().UTC())
		return err
	})
	if err != nil {
		if created != nil { // the object store has an upload the database does not know about
			s.terminate(ctx, created)
		}
		return nil, tusError(err)
	}
	return &tusUpload{inner: created, assetID: a.ID, s: s}, nil
}

// terminate removes what NewUpload created when the database step failed. Best effort: anything
// left is found by the storage-enumerating purge and by expiry.
func (s *TusStore) terminate(ctx context.Context, up handler.Upload) {
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := s.inner.AsTerminatableUpload(up).Terminate(c); err != nil {
		httpx.Logger(ctx).WarnContext(c, "tus cleanup failed",
			slog.String("error", storage.Sanitize("tus_terminate", keys.Source, err).Error()))
	}
}

// GetUpload opens the upload of the grant's asset. The ID is the asset ID, the only identifier
// clients ever see; any other value, or another asset's ID, is not found.
func (s *TusStore) GetUpload(ctx context.Context, idText string) (handler.Upload, error) {
	g, ok := GrantFrom(ctx)
	if !ok {
		return nil, errTusNoGrant
	}
	aid, err := id.Parse[id.AssetKind](idText)
	if err != nil || aid != g.Asset.ID {
		return nil, handler.ErrNotFound
	}
	cur, err := s.repos.GetAsset(ctx, g.Asset.TenantID, aid) // fresh: the upload ID may be new
	if err != nil {
		return nil, tusError(err)
	}
	if cur.UploadMethod != db.UploadTus || cur.S3UploadID == "" || !cur.State.Accepting() {
		return nil, handler.ErrNotFound
	}
	inner, err := s.inner.GetUpload(ctx, cur.SourceKey+"+"+cur.S3UploadID)
	if err != nil {
		return nil, s.fail(ctx, "tus_open", err)
	}
	return &tusUpload{inner: inner, assetID: aid, s: s}, nil
}

// tusUpload hides the object key, the object store's upload ID and all metadata from tusd's
// responses, and sanitises errors.
type tusUpload struct {
	inner   handler.Upload
	assetID id.AssetID
	s       *TusStore
}

var _ handler.Upload = (*tusUpload)(nil)

func (u *tusUpload) WriteChunk(ctx context.Context, offset int64, src io.Reader) (int64, error) {
	n, err := u.inner.WriteChunk(ctx, offset, src)
	return n, u.s.fail(ctx, "tus_write_chunk", err)
}

func (u *tusUpload) GetInfo(ctx context.Context) (handler.FileInfo, error) {
	info, err := u.inner.GetInfo(ctx)
	if err != nil {
		return handler.FileInfo{}, u.s.fail(ctx, "tus_info", err)
	}
	info.ID = u.assetID.String()
	info.MetaData = nil
	info.Storage = nil
	return info, nil
}

// GetReader refuses: the source is never served back through edge.
func (u *tusUpload) GetReader(context.Context) (io.ReadCloser, error) { return nil, errTusNoRead }

func (u *tusUpload) FinishUpload(ctx context.Context) error {
	return u.s.fail(ctx, "tus_finish", u.inner.FinishUpload(ctx))
}

// safeError is what tusd sees instead of an object-store error: a fixed message (tusd copies
// err.Error() into the response body) with the original reachable through Unwrap, so tusd's own
// errors.Is checks (a cancelled or interrupted request) still work.
type safeError struct{ cause error }

func (*safeError) Error() string { return "storage error" }

func (e *safeError) Unwrap() error { return e.cause }

// fail makes err safe for tusd: tusd's own protocol errors pass through; anything else is logged
// as kind, operation and S3 code only (never a URL or key) and replaced by a fixed message.
func (s *TusStore) fail(ctx context.Context, op string, err error) error {
	if err == nil {
		return nil
	}
	var he handler.Error
	if errors.As(err, &he) {
		return he
	}
	if ctx.Err() == nil { // an interrupted request is not worth an error line
		httpx.Logger(ctx).ErrorContext(ctx, "upload storage error",
			slog.String("error", storage.Sanitize(op, keys.Source, err).Error()))
	}
	return &safeError{cause: err}
}

// tusError turns a database or protocol error into one tusd can send. Only fixed texts reach
// the response.
func tusError(err error) error {
	var he handler.Error
	if errors.As(err, &he) {
		return he
	}
	var se *safeError
	if errors.As(err, &se) {
		return se
	}
	var e *errs.Error
	if errors.As(err, &e) && e.Code == errs.NotFound {
		return handler.ErrNotFound
	}
	return errTusInternal
}
