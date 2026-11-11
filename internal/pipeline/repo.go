package pipeline

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
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
	DeleteHLSArtifacts(ctx context.Context, asset id.AssetID) (int64, error)
	// DeleteManifest removes the asset's integrity manifest, if it has one.
	DeleteManifest(ctx context.Context, asset id.AssetID) (bool, error)
	// Complete registers every artifact, stores c.Manifest and moves the asset processing -> ready
	// in ONE transaction, so a ready asset always has its full artifact registry and its manifest.
	Complete(ctx context.Context, tenant id.TenantID, asset id.AssetID, arts []db.Artifact, c db.Completion) (db.Asset, error)
}

// DBRepo is the Postgres implementation of Repo.
type DBRepo struct {
	*db.Repos
	pool *pgxpool.Pool
}

// NewDBRepo returns a Repo over pool.
func NewDBRepo(pool *pgxpool.Pool) *DBRepo { return &DBRepo{Repos: db.New(pool), pool: pool} }

// Complete implements Repo.
func (r *DBRepo) Complete(ctx context.Context, tenant id.TenantID, asset id.AssetID, arts []db.Artifact, c db.Completion) (db.Asset, error) {
	var out db.Asset
	err := db.Tx(ctx, r.pool, func(tx *db.Repos) error {
		for _, a := range arts {
			if err := tx.RecordArtifact(ctx, a); err != nil {
				return err
			}
		}
		var err error
		out, err = tx.CompleteProcessing(ctx, tenant, asset, c)
		return err
	})
	return out, err
}

// Key is the part of a content key the pipeline uses. contentkey.ContentKey implements it: Bytes
// returns a copy the caller must clear, and Zero wipes the key's own buffer.
type Key interface {
	Bytes() []byte
	Zero()
}

// KeyEnsurer returns the asset's content key, creating it first when the asset has none.
type KeyEnsurer interface {
	Ensure(ctx context.Context, tenant id.TenantID, asset id.AssetID) (Key, error)
}

var _ Key = contentkey.ContentKey{}

// ContentKeys is the KeyEnsurer over the content key manager.
type ContentKeys struct {
	Pool    *pgxpool.Pool
	Manager *contentkey.Manager
}

// Ensure creates the asset's content key exactly once and returns it. The key is created here,
// once, before any transcoding starts, and a retried job finds and reuses it: it is never created
// lazily inside per-rendition work, where two renditions could race to create it. The asset row is
// locked for the length of the creating transaction, so two concurrent attempts serialise and the
// second one finds the key the first created.
func (c ContentKeys) Ensure(ctx context.Context, tenant id.TenantID, asset id.AssetID) (Key, error) {
	k, err := c.Manager.Get(ctx, tenant, asset)
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
		created, err := c.Manager.Create(ctx, tx, tenant, asset)
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
	k, err = c.Manager.Get(ctx, tenant, asset)
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
