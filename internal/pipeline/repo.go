package pipeline

import (
	"context"
	"errors"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/anchor"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Repo is the database access the pipeline needs. DBRepo implements it over Postgres; the unit
// tests use an in-memory fake.
type Repo interface {
	GetAsset(ctx context.Context, tenant id.TenantID, asset id.AssetID) (db.Asset, error)
	// TransitionAsset is a compare-and-set along an edge of the asset lifecycle.
	TransitionAsset(ctx context.Context, tenant id.TenantID, asset id.AssetID, t db.Transition) (db.Asset, error)
	RecordSource(ctx context.Context, tenant id.TenantID, asset id.AssetID, sha256 []byte, size int64) error
	SetProgress(ctx context.Context, tenant id.TenantID, asset id.AssetID, percent int) error
	ResetProgress(ctx context.Context, tenant id.TenantID, asset id.AssetID) error
	// DeleteHLSArtifacts removes one variant's artifact rows (db.VariantOriginal or db.VariantMasked).
	DeleteHLSArtifacts(ctx context.Context, asset id.AssetID, variant string) (int64, error)
	// DeleteManifest removes the asset's integrity manifest, if it has one.
	DeleteManifest(ctx context.Context, asset id.AssetID) (bool, error)
	// GetManifest returns the asset's stored manifest (not_found when it has none).
	GetManifest(ctx context.Context, asset id.AssetID) (db.AssetManifest, error)
	// Complete registers every artifact, stores c.Manifest and moves the asset processing -> ready
	// in ONE transaction, so a ready asset always has its full artifact registry and its manifest.
	Complete(ctx context.Context, tenant id.TenantID, asset id.AssetID, arts []db.Artifact, c db.Completion) (db.Asset, error)
	// CompleteMasking registers the masked variant's artifacts, replaces the manifest with the
	// re-signed one and sets masking_state ready with the face count, in ONE transaction. It is a
	// state conflict (db.ErrStateChanged) unless the asset is still ready.
	CompleteMasking(ctx context.Context, tenant id.TenantID, asset id.AssetID, arts []db.Artifact, m db.AssetManifest, faces int, at time.Time) error
	// SetMasking records the masking state (and the face count, when known) of a masking asset.
	SetMasking(ctx context.Context, tenant id.TenantID, asset id.AssetID, state string, faces *int, at time.Time) error
}

// DBRepo is the Postgres implementation of Repo.
type DBRepo struct {
	*db.Repos
	pool *pgxpool.Pool
	// anchor, when set, receives a manifest.anchor job in the transaction that stores a manifest
	// (ADR 0041).
	anchor anchor.Enqueuer
}

// WithAnchor makes the repository enqueue a manifest.anchor job with every manifest it stores.
func (r *DBRepo) WithAnchor(q anchor.Enqueuer) *DBRepo {
	r.anchor = q
	return r
}

// NewDBRepo returns a Repo over pool.
func NewDBRepo(pool *pgxpool.Pool) *DBRepo { return &DBRepo{Repos: db.New(pool), pool: pool} }

// inTx runs fn in a transaction, handing it the raw transaction too (jobs are inserted with it).
func inTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx, *db.Repos) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return db.MapError(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() // a no-op after Commit
	if err := fn(tx, db.New(tx)); err != nil {
		return err
	}
	return db.MapError(tx.Commit(ctx))
}

// Complete implements Repo.
func (r *DBRepo) Complete(ctx context.Context, tenant id.TenantID, asset id.AssetID, arts []db.Artifact, c db.Completion) (db.Asset, error) {
	var out db.Asset
	err := inTx(ctx, r.pool, func(tx pgx.Tx, repos *db.Repos) error {
		for _, a := range arts {
			if err := repos.RecordArtifact(ctx, a); err != nil {
				return err
			}
		}
		var err error
		out, err = repos.CompleteProcessing(ctx, tenant, asset, c)
		if err != nil || c.Manifest == nil {
			return err
		}
		return r.enqueueAnchor(ctx, tx, tenant, asset, c.Manifest.PayloadSHA256)
	})
	return out, err
}

// CompleteMasking implements Repo.
func (r *DBRepo) CompleteMasking(ctx context.Context, tenant id.TenantID, asset id.AssetID, arts []db.Artifact, m db.AssetManifest, faces int, at time.Time) error {
	return inTx(ctx, r.pool, func(rawTx pgx.Tx, tx *db.Repos) error {
		cur, err := tx.LockAsset(ctx, tenant, asset)
		if err != nil {
			return err
		}
		if cur.State != db.AssetReady || !cur.MaskFaces {
			return errs.Wrap(errs.Conflict, "the asset can no longer receive a masked variant", db.ErrStateChanged)
		}
		for _, a := range arts {
			if err := tx.RecordArtifact(ctx, a); err != nil {
				return err
			}
		}
		// The manifest is replaced by the one that also covers the masked variant.
		if _, err := tx.DeleteManifest(ctx, asset); err != nil {
			return err
		}
		if err := tx.InsertManifest(ctx, m); err != nil {
			return err
		}
		// The new row has no token; the old one went with the old row. Anchor the new payload.
		if err := r.enqueueAnchor(ctx, rawTx, tenant, asset, m.PayloadSHA256); err != nil {
			return err
		}
		_, err = tx.SetAssetMasking(ctx, tenant, asset, db.MaskingReady, &faces, at)
		return err
	})
}

func (r *DBRepo) enqueueAnchor(ctx context.Context, tx pgx.Tx, tenant id.TenantID, asset id.AssetID, payloadSHA256 []byte) error {
	if r.anchor == nil {
		return nil
	}
	return anchor.Enqueue(ctx, r.anchor, tx, tenant, asset, payloadSHA256)
}

// SetMasking implements Repo.
func (r *DBRepo) SetMasking(ctx context.Context, tenant id.TenantID, asset id.AssetID, state string, faces *int, at time.Time) error {
	_, err := r.SetAssetMasking(ctx, tenant, asset, state, faces, at)
	return err
}

// Tasks is the hand-off table access asset.mask needs (ADR 0010).
type Tasks interface {
	// Create writes a hand-off row for env (and the River job that awaits it) in its own transaction.
	Create(ctx context.Context, env jobs.Envelope, opts *jobs.TaskOpts) (jobs.Task, error)
	Get(ctx context.Context, taskID uuid.UUID) (jobs.Task, error)
}

// DBTasks is the Tasks over Postgres.
type DBTasks struct {
	Pool  *pgxpool.Pool
	Queue *jobs.Queue
}

// Create implements Tasks.
func (t DBTasks) Create(ctx context.Context, env jobs.Envelope, opts *jobs.TaskOpts) (jobs.Task, error) {
	var task jobs.Task
	err := inTx(ctx, t.Pool, func(tx pgx.Tx, _ *db.Repos) error {
		var err error
		task, err = t.Queue.CreateTask(ctx, tx, env, opts)
		return err
	})
	return task, err
}

// Get implements Tasks.
func (t DBTasks) Get(ctx context.Context, taskID uuid.UUID) (jobs.Task, error) {
	return jobs.GetTask(ctx, t.Pool, taskID)
}

// Key is the part of a content key the pipeline uses. contentkey.ContentKey implements it: Bytes
// returns a copy the caller must clear, and Zero wipes the key's own buffer.
type Key interface {
	Bytes() []byte
	Zero()
}

// KeyEnsurer returns the asset's content key of one variant, creating it first when there is none.
type KeyEnsurer interface {
	Ensure(ctx context.Context, tenant id.TenantID, asset id.AssetID, variant keys.Variant) (Key, error)
}

var _ Key = contentkey.ContentKey{}

// ContentKeys is the KeyEnsurer over the content key manager.
type ContentKeys struct {
	Pool    *pgxpool.Pool
	Manager *contentkey.Manager
}

// Ensure creates the asset's content key of the variant exactly once and returns it. The key is created here,
// once, before any transcoding starts, and a retried job finds and reuses it: it is never created
// lazily inside per-rendition work, where two renditions could race to create it. The asset row is
// locked for the length of the creating transaction, so two concurrent attempts serialise and the
// second one finds the key the first created.
func (c ContentKeys) Ensure(ctx context.Context, tenant id.TenantID, asset id.AssetID, variant keys.Variant) (Key, error) {
	k, err := c.Manager.Get(ctx, tenant, asset, variant)
	if err == nil {
		return k, nil
	}
	if !isCode(err, errs.NotFound) {
		return nil, err
	}
	err = db.Tx(ctx, c.Pool, func(tx *db.Repos) error {
		if _, err := tx.LockAsset(ctx, tenant, asset); err != nil {
			return err
		}
		created, err := c.Manager.Create(ctx, tx, tenant, asset, variant)
		if err == nil {
			created.Zero()
			return nil
		}
		if isCode(err, errs.Conflict) {
			return nil // another attempt created it between our read and the lock
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	k, err = c.Manager.Get(ctx, tenant, asset, variant)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func isCode(err error, code errs.Code) bool {
	var e *errs.Error
	return errors.As(err, &e) && e.Code == code
}

// Toolchain is what the pipeline needs from FFmpeg and FFprobe. media.Tools implements it.
type Toolchain interface {
	Probe(ctx context.Context, path string) (media.Info, error)
	Transcode(ctx context.Context, spec media.TranscodeSpec, progress func(done time.Duration)) error
	// Version returns the first line of `ffmpeg -version`.
	Version(ctx context.Context) (string, error)
}

var _ Toolchain = media.Tools{}
