package uploads

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Audit actions written by Service (the audit_events.action column).
const (
	AuditAssetCreate = "asset.create"
	AuditAssetCommit = "asset.commit"
	AuditAssetAbort  = "asset.abort"
)

// FailureUploadAborted is the failure code of an asset whose upload was aborted.
const FailureUploadAborted = "upload_aborted"

// ProcessKind is the job kind enqueued when an upload is committed. Its handler arrives with the
// processing task (M3-3); until then the job waits in the queue. Do not rename it once jobs of
// that kind exist.
const ProcessKind = "asset.process"

// ProcessArgs are the arguments of the asset.process job: identifiers only. No object key,
// token or URL is ever put in a job; the worker reads the asset row to find its source.
type ProcessArgs struct {
	TenantID id.TenantID `json:"tenant_id"`
	AssetID  id.AssetID  `json:"asset_id"`
}

// Kind implements jobs.Args.
func (ProcessArgs) Kind() string { return ProcessKind }

// Enqueuer inserts a job in the caller's transaction. *jobs.Queue implements it.
type Enqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, args jobs.Args, opts *jobs.EnqueueOpts) (int64, error)
}

// Deps are the collaborators of a Service.
type Deps struct {
	Pool   *pgxpool.Pool
	Source storage.Store // the source bucket
	Queue  Enqueuer
	Limits Limits
	// EdgeURL is the public base URL of the edge listener, without a trailing slash.
	EdgeURL string
	Log     *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service implements the asset operations of the API: create, read, list, commit and abort.
// Every method is scoped to a tenant. Safe for concurrent use.
type Service struct {
	pool   *pgxpool.Pool
	repos  *db.Repos
	source storage.Store
	queue  Enqueuer
	limits Limits
	edge   string
	log    *slog.Logger
	now    func() time.Time
}

// NewService builds a Service. It rejects invalid limits.
func NewService(d Deps) (*Service, error) {
	if d.Pool == nil || d.Source == nil || d.Queue == nil {
		return nil, errors.New("uploads: a pool, the source store and a job queue are required")
	}
	if d.EdgeURL == "" {
		return nil, errors.New("uploads: the edge public URL is required")
	}
	if err := d.Limits.Validate(); err != nil {
		return nil, err
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{
		pool: d.Pool, repos: db.New(d.Pool), source: d.Source, queue: d.Queue, limits: d.Limits,
		edge: d.EdgeURL, log: d.Log, now: d.Now,
	}, nil
}

// Limits returns the limits in force.
func (s *Service) Limits() Limits { return s.limits }

// Actor identifies who performs an operation, for the audit row.
type Actor = auth.Actor

// CreateInput is the input of Create.
type CreateInput struct {
	TenantID    id.TenantID
	Actor       Actor
	SizeBytes   int64
	ContentType string
	Method      db.UploadMethod
}

// Instructions tell the caller how to upload. Token is the only place the upload token ever
// appears.
type Instructions struct {
	Method    db.UploadMethod
	URL       string // tus creation endpoint, or the multipart parts base URL
	Token     Token
	ExpiresAt time.Time
	PartBytes int64 // multipart only
}

// Created is the result of Create.
type Created struct {
	Asset  db.Asset
	Upload Instructions
}

// Create makes an asset in state created, starts the object-store side of a multipart upload and
// issues the upload token, all so that nothing is returned unless the asset row exists.
func (s *Service) Create(ctx context.Context, in CreateInput) (Created, error) {
	if !in.Method.Valid() {
		return Created{}, errs.New(errs.InvalidRequest, "upload_method must be tus or multipart.")
	}
	if err := s.limits.CheckSize(in.SizeBytes); err != nil {
		return Created{}, err
	}
	if err := CheckContentType(in.ContentType); err != nil {
		return Created{}, err
	}
	tok, err := NewToken()
	if err != nil {
		return Created{}, errs.Wrap(errs.InternalError, "An internal error occurred.", err)
	}

	assetID := id.New[id.AssetKind]()
	key := keys.NewSource(in.TenantID, assetID)
	expires := s.now().UTC().Add(s.limits.TokenTTL)

	var uploadID string
	if in.Method == db.UploadMultipart {
		if uploadID, err = s.source.CreateMultipart(ctx, key, in.ContentType); err != nil {
			return Created{}, storage.ToAppError(err)
		}
	}
	var asset db.Asset
	err = db.Tx(ctx, s.pool, func(r *db.Repos) error {
		var err error
		asset, err = r.CreateUploadAsset(ctx, db.NewUploadAsset{
			ID: assetID, TenantID: in.TenantID, ClientID: in.Actor.ClientID, SizeBytes: in.SizeBytes,
			ContentType: in.ContentType, Method: in.Method, SourceKey: key, S3UploadID: uploadID, ExpiresAt: expires,
		})
		if err != nil {
			return err
		}
		if err := r.InsertUploadToken(ctx, in.TenantID, assetID, tok.Hash(), expires); err != nil {
			return err
		}
		return s.audit(ctx, r, in.TenantID, in.Actor, AuditAssetCreate, assetID)
	})
	if err != nil {
		if uploadID != "" { // do not leave an orphaned multipart upload behind
			s.cleanup(ctx, "create", func(c context.Context) error { return s.source.AbortMultipart(c, key, uploadID) })
		}
		return Created{}, err
	}
	return Created{Asset: asset, Upload: s.instructions(asset, tok, expires)}, nil
}

func (s *Service) instructions(a db.Asset, tok Token, expires time.Time) Instructions {
	ins := Instructions{Method: a.UploadMethod, Token: tok, ExpiresAt: expires}
	switch a.UploadMethod {
	case db.UploadTus:
		ins.URL = s.edge + "/v1/uploads/tus/"
	case db.UploadMultipart:
		ins.URL = s.edge + "/v1/uploads/multipart/" + a.ID.String() + "/parts/"
		ins.PartBytes = s.limits.PartBytes
	}
	return ins
}

// Get returns one asset of the tenant. A deleted asset is not_found, like another tenant's.
func (s *Service) Get(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) (db.Asset, error) {
	a, err := s.repos.GetAsset(ctx, tenantID, assetID)
	if err != nil {
		return db.Asset{}, err
	}
	if a.State == db.AssetDeleted {
		return db.Asset{}, errs.New(errs.NotFound, "No such asset.")
	}
	return a, nil
}

// List returns one page of the tenant's assets, oldest first, and the cursor of the next page
// (the zero ID when there is none).
func (s *Service) List(ctx context.Context, tenantID id.TenantID, after id.AssetID, limit int) ([]db.Asset, id.AssetID, error) {
	rows, err := s.repos.ListAssetsPage(ctx, tenantID, after, limit+1)
	if err != nil {
		return nil, id.AssetID{}, err
	}
	var next id.AssetID
	if len(rows) > limit {
		rows = rows[:limit]
		next = rows[limit-1].ID
	}
	return rows, next, nil
}

// Commit finishes the upload of an asset and hands it to processing: it completes a multipart
// upload from the parts edge recorded, verifies that the source object exists with exactly the
// declared size, then in one transaction moves the asset to committed, ends the upload token and
// enqueues asset.process. It is idempotent: committing an asset that is already committed (or
// further along) returns it without enqueueing again.
func (s *Service) Commit(ctx context.Context, tenantID id.TenantID, actor Actor, assetID id.AssetID) (db.Asset, error) {
	a, err := s.Get(ctx, tenantID, assetID)
	if err != nil {
		return db.Asset{}, err
	}
	switch a.State {
	case db.AssetCommitted, db.AssetProcessing, db.AssetReady:
		return a, nil
	case db.AssetUploading:
	case db.AssetCreated:
		return db.Asset{}, errs.New(errs.Conflict, "The upload has not started.")
	default:
		return db.Asset{}, errs.New(errs.Conflict, "The asset can no longer be committed.")
	}
	if err := s.limits.CheckSize(a.SizeBytes); err != nil {
		return db.Asset{}, err
	}
	if err := s.completeSource(ctx, a); err != nil {
		return db.Asset{}, err
	}

	var committed db.Asset
	err = s.inTx(ctx, func(tx pgx.Tx, r *db.Repos) error {
		var err error
		committed, err = r.TransitionAsset(ctx, tenantID, assetID, db.Transition{
			From: db.AssetUploading, To: db.AssetCommitted, At: s.now().UTC(),
		})
		if err != nil {
			return err
		}
		if err := r.DeleteUploadTokens(ctx, assetID); err != nil {
			return err
		}
		if err := r.DeleteUploadParts(ctx, assetID); err != nil {
			return err
		}
		if err := s.audit(ctx, r, tenantID, actor, AuditAssetCommit, assetID); err != nil {
			return err
		}
		_, err = s.queue.Enqueue(ctx, tx, ProcessArgs{TenantID: tenantID, AssetID: assetID}, nil)
		return err
	})
	if errors.Is(err, db.ErrStateChanged) {
		// Another commit (or an abort) won. Report where the asset is now.
		cur, gerr := s.Get(ctx, tenantID, assetID)
		if gerr == nil && (cur.State == db.AssetCommitted || cur.State == db.AssetProcessing || cur.State == db.AssetReady) {
			return cur, nil
		}
		return db.Asset{}, errs.New(errs.Conflict, "The asset can no longer be committed.")
	}
	if err != nil {
		return db.Asset{}, err
	}
	return committed, nil
}

// completeSource makes sure the source object exists with the declared size, completing a
// multipart upload first when needed. A retry after a failed commit finds the object already
// assembled and skips the completion.
func (s *Service) completeSource(ctx context.Context, a db.Asset) error {
	info, err := s.source.Head(ctx, a.SourceKey)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return storage.ToAppError(err)
	}
	if err != nil { // no object yet
		if a.UploadMethod != db.UploadMultipart {
			return errs.New(errs.Conflict, "The upload is not complete.")
		}
		if err := s.completeMultipart(ctx, a); err != nil {
			return err
		}
		if info, err = s.source.Head(ctx, a.SourceKey); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return errs.New(errs.Conflict, "The upload is not complete.")
			}
			return storage.ToAppError(err)
		}
	}
	if info.Size > s.limits.MaxSourceBytes {
		return errs.New(errs.PayloadTooLarge, "The uploaded object exceeds the maximum source size.")
	}
	if info.Size != a.SizeBytes {
		return errs.New(errs.Conflict, "The uploaded object does not have the declared size.")
	}
	return nil
}

func (s *Service) completeMultipart(ctx context.Context, a db.Asset) error {
	if a.S3UploadID == "" {
		return errs.New(errs.Conflict, "The upload is not complete.")
	}
	parts, err := s.repos.ListUploadParts(ctx, a.ID)
	if err != nil {
		return err
	}
	if err := ValidateParts(parts, a.SizeBytes, s.limits.PartBytes); err != nil {
		return err
	}
	done := make([]storage.CompletedPart, len(parts))
	for i, p := range parts {
		done[i] = storage.CompletedPart{PartNumber: int32(p.PartNumber), ETag: p.ETag} //nolint:gosec // 1..10000
	}
	if err := s.source.CompleteMultipart(ctx, a.SourceKey, a.S3UploadID, done); err != nil {
		if storage.KindOf(err) == storage.NotFound || storage.KindOf(err) == storage.Invalid {
			// The object store no longer knows the upload, or a recorded part is stale (a part
			// was replaced while this commit ran). The client can re-send the part and commit again.
			return errs.Wrap(errs.Conflict, "The uploaded parts could not be assembled; upload them again and retry.", err)
		}
		return storage.ToAppError(err)
	}
	return nil
}

// Abort stops an upload that has not been committed: the asset becomes failed with the code
// upload_aborted, its token and part records end, an object-store multipart upload is aborted and
// every object under the asset's source prefix (the tus data and its .info file included) is
// deleted. Aborting twice repeats the cleanup and succeeds, so a failed cleanup can be retried.
func (s *Service) Abort(ctx context.Context, tenantID id.TenantID, actor Actor, assetID id.AssetID) (db.Asset, error) {
	a, err := s.Get(ctx, tenantID, assetID)
	if err != nil {
		return db.Asset{}, err
	}
	switch {
	case a.State.Accepting():
		err = db.Tx(ctx, s.pool, func(r *db.Repos) error {
			var err error
			a, err = r.TransitionAsset(ctx, tenantID, assetID, db.Transition{
				From: a.State, To: db.AssetFailed, FailureCode: FailureUploadAborted, At: s.now().UTC(),
			})
			if err != nil {
				return err
			}
			if err := r.DeleteUploadTokens(ctx, assetID); err != nil {
				return err
			}
			if err := r.DeleteUploadParts(ctx, assetID); err != nil {
				return err
			}
			return s.audit(ctx, r, tenantID, actor, AuditAssetAbort, assetID)
		})
		if errors.Is(err, db.ErrStateChanged) {
			return db.Asset{}, errs.New(errs.Conflict, "The asset can no longer be aborted.")
		}
		if err != nil {
			return db.Asset{}, err
		}
	case a.State == db.AssetFailed && a.FailureCode == FailureUploadAborted:
		// Already aborted: fall through to repeat the cleanup.
	default:
		return db.Asset{}, errs.New(errs.Conflict, "The upload was already committed or the asset has failed; it cannot be aborted.")
	}
	if err := s.deleteSource(ctx, a); err != nil {
		return db.Asset{}, err
	}
	return a, nil
}

// deleteSource removes everything stored for the asset in the source bucket.
func (s *Service) deleteSource(ctx context.Context, a db.Asset) error {
	if a.S3UploadID != "" && a.SourceKey != "" {
		if err := s.source.AbortMultipart(ctx, a.SourceKey, a.S3UploadID); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return storage.ToAppError(err)
		}
	}
	for _, p := range keys.AssetPrefixes(a.TenantID, a.ID) {
		if p.Bucket != keys.Source {
			continue
		}
		var batch []string
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			err := s.source.DeleteBatch(ctx, batch)
			batch = batch[:0]
			return storage.ToAppError(err)
		}
		for o, err := range storage.ListAll(ctx, s.source, p.Prefix) {
			if err != nil {
				return storage.ToAppError(err)
			}
			if batch = append(batch, o.Key); len(batch) >= storage.MaxDeleteBatch {
				if err := flush(); err != nil {
					return err
				}
			}
		}
		if err := flush(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) audit(ctx context.Context, r *db.Repos, tenantID id.TenantID, actor Actor, action string, assetID id.AssetID) error {
	_, err := r.InsertAuditEvent(ctx, db.NewAuditEvent{
		TenantID: tenantID, ClientID: actor.ClientID, APIKeyID: actor.KeyID,
		Action: action, Target: assetID.String(), RequestID: actor.RequestID,
	})
	return err
}

// inTx runs fn in a transaction that fn can also hand to the job queue.
func (s *Service) inTx(ctx context.Context, fn func(pgx.Tx, *db.Repos) error) (err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return db.MapError(err)
	}
	done := false
	defer func() {
		if !done {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	if err := fn(tx, db.New(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return db.MapError(err)
	}
	done = true
	return nil
}

// cleanup runs a best-effort compensation on a context that survives the request's cancellation.
func (s *Service) cleanup(ctx context.Context, op string, fn func(context.Context) error) {
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := fn(c); err != nil {
		s.log.WarnContext(c, "upload cleanup failed", slog.String("op", op), slog.String("error", err.Error()))
	}
}
