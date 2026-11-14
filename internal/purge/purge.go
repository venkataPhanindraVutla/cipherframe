package purge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// JobKind is the River job kind of the purge. Do not rename it once jobs of that kind exist.
const JobKind = "asset.delete"

// Audit actions written by the purge machinery.
const (
	AuditAssetDelete = "asset.delete" // an API call asked for the deletion
	AuditAssetExpire = "asset.expire" // the retention job did
	AuditAssetPurged = "asset.purged" // the purge finished and storage was verified empty
)

// DeleteArgs are the arguments of the asset.delete job: identifiers and the reason only.
type DeleteArgs struct {
	TenantID id.TenantID `json:"tenant_id"`
	AssetID  id.AssetID  `json:"asset_id"`
	// Reason is db.DeletionRequested or db.DeletionRetention.
	Reason string `json:"reason"`
}

// Kind implements jobs.Args.
func (DeleteArgs) Kind() string { return JobKind }

// Job tuning. The job runs on the default queue (it is I/O, not CPU).
const (
	jobTimeout     = 30 * time.Minute
	jobMaxAttempts = 8
	// maxPasses bounds how often one run lists and deletes before it gives up and fails loudly.
	maxPasses = 4
	// inFlightPoll and DefaultInFlightWait: while an asset.process or asset.mask job of the asset is
	// still active the purge waits (the job stops at its next check), up to this long after the
	// deletion was requested.
	inFlightPoll        = 15 * time.Second
	DefaultInFlightWait = 2 * time.Hour
)

// ErrLeftovers is returned when objects remain after every pass. The job retries; once it is out
// of attempts it is dead-lettered and the asset stays deleting, which is visible in the API.
var ErrLeftovers = errors.New("purge: objects remain under the asset's prefixes after deletion")

// Deps are the collaborators of the Purger.
type Deps struct {
	Pool     *pgxpool.Pool
	Source   storage.Store // the source bucket
	Delivery storage.Store // the delivery bucket
	Keys     *contentkey.Manager
	// Signer signs the deletion record with the current signing key (M6-3). It is required.
	Signer signing.Signer
	Log    *slog.Logger
	// InFlightWait overrides DefaultInFlightWait when positive.
	InFlightWait time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

// Purger runs asset.delete jobs.
type Purger struct {
	Deps
	repos *db.Repos
}

// New validates deps and returns a Purger.
func New(d Deps) (*Purger, error) {
	if d.Pool == nil || d.Source == nil || d.Delivery == nil || d.Keys == nil || d.Signer == nil {
		return nil, errors.New("purge: a pool, both stores, the content key manager and a signer are required")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.InFlightWait <= 0 {
		d.InFlightWait = DefaultInFlightWait
	}
	return &Purger{Deps: d, repos: db.New(d.Pool)}, nil
}

// Register registers asset.delete on the default queue.
func Register(reg *jobs.Registry, d Deps) error {
	p, err := New(d)
	if err != nil {
		return err
	}
	return jobs.Register(reg, p.Handle, jobs.KindConfig{Timeout: jobTimeout, MaxAttempts: jobMaxAttempts})
}

// Declare tells a process that only inserts jobs (the api role, the retention sweeper) how
// asset.delete is configured.
func Declare(reg *jobs.Registry) error {
	return jobs.Declare[DeleteArgs](reg, jobs.KindConfig{MaxAttempts: jobMaxAttempts})
}

// Handle works one asset.delete job. Every step is idempotent, so a retry, or two jobs for one
// asset, end in the same place.
//
//  1. Mark the asset deleting (when the job was enqueued without the API's marking): playback,
//     session creation, uploads and the pipeline refuse it from here on.
//  2. Wait for any in-flight asset.process or asset.mask job of the asset to finish; they stop at
//     their next check and clean up after themselves.
//  3. Revoke the asset's active playback sessions.
//  4. Enumerate storage under every prefix (never the database alone), delete in batches and list
//     again until a pass finds nothing. Objects left after maxPasses fail the job (ErrLeftovers).
//  5. In one transaction: destroy the content keys, drop the registry rows and the manifest, store
//     the signed deletion record and move the asset to deleted (the tombstone).
func (p *Purger) Handle(ctx context.Context, job jobs.Job[DeleteArgs]) error {
	tenant, assetID := job.Args.TenantID, job.Args.AssetID
	if tenant.IsZero() || assetID.IsZero() || !db.ValidDeletionReason(job.Args.Reason) {
		return jobs.Cancel(errs.New(errs.InvalidRequest, "the job has no asset"))
	}
	log := p.Log.With(slog.String("job", JobKind), slog.String("tenant_id", tenant.String()),
		slog.String("asset_id", assetID.String()), slog.Int("attempt", job.Attempt))

	asset, err := p.repos.GetAsset(ctx, tenant, assetID)
	if err != nil {
		if isNotFound(err) {
			return jobs.Cancel(err)
		}
		return err
	}
	switch asset.State {
	case db.AssetDeleted:
		log.InfoContext(ctx, "nothing to do: the asset is already deleted")
		return nil
	case db.AssetDeleting:
	default:
		if asset, err = p.repos.RequestAssetDeletion(ctx, tenant, assetID, job.Args.Reason, p.Now().UTC()); err != nil {
			if errors.Is(err, db.ErrStateChanged) { // another job marked it first
				if asset, err = p.repos.GetAsset(ctx, tenant, assetID); err != nil {
					return err
				}
			} else {
				return err
			}
		}
	}

	active, err := ActiveJobs(ctx, p.Pool, assetID, "asset.process", "asset.mask")
	if err != nil {
		return err
	}
	if active && p.Now().Sub(*asset.DeletionRequestedAt) < p.InFlightWait {
		log.InfoContext(ctx, "waiting for an in-flight processing job to stop")
		return jobs.Snooze(inFlightPoll)
	}
	if active {
		log.WarnContext(ctx, "an in-flight processing job did not stop in time; purging anyway (it removes its own output)")
	}

	if err := p.revokeSessions(ctx, asset); err != nil {
		return err
	}
	tally, err := p.purgeStorage(ctx, asset, log)
	if err != nil {
		return err
	}
	return p.finish(ctx, asset, tally, log)
}

// revokeSessions ends the asset's active playback sessions and records the revocations in the
// access trail, like any other revocation.
func (p *Purger) revokeSessions(ctx context.Context, asset db.Asset) error {
	now := p.Now().UTC().Truncate(time.Microsecond)
	refs, err := p.repos.RevokePlaybackSessionsByFilter(ctx, asset.TenantID, "", asset.ID, "asset_deleted", now)
	if err != nil || len(refs) == 0 {
		return err
	}
	rows := make([]db.AccessLogRow, len(refs))
	for i, r := range refs {
		rows[i] = db.AccessLogRow{
			TenantID: r.TenantID, AssetID: r.AssetID, SessionHash: r.IDHash, ViewerID: r.ViewerID,
			AuthMethod: r.AuthMethod, Event: db.AccessRevoked, At: now,
		}
	}
	return p.repos.InsertAccessLog(ctx, rows)
}

// tally counts what the purge deleted, per bucket, kind and variant.
type tally struct {
	classes map[Class]count
	seen    map[string]bool // bucket/key, so an object found again is not counted twice
}

type count struct {
	Objects int64
	Bytes   int64
}

func newTally() *tally { return &tally{classes: map[Class]count{}, seen: map[string]bool{}} }

func (t *tally) add(c Class, key string, size int64) {
	k := string(c.Bucket) + "/" + key
	if t.seen[k] {
		return
	}
	t.seen[k] = true
	cur := t.classes[c]
	cur.Objects++
	cur.Bytes += size
	t.classes[c] = cur
}

// purgeStorage deletes everything under every asset prefix and verifies it is gone.
func (p *Purger) purgeStorage(ctx context.Context, asset db.Asset, log *slog.Logger) (*tally, error) {
	if asset.S3UploadID != "" && asset.SourceKey != "" {
		// An unfinished multipart upload holds parts that List cannot see.
		if err := p.Source.AbortMultipart(ctx, asset.SourceKey, asset.S3UploadID); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ToAppError(err)
		}
	}
	t := newTally()
	for pass := 1; pass <= maxPasses; pass++ {
		found, err := p.sweep(ctx, asset, t)
		if err != nil {
			return nil, err
		}
		if found == 0 {
			if pass > 1 {
				log.InfoContext(ctx, "storage verified empty", slog.Int("passes", pass))
			}
			return t, nil
		}
		if pass > 1 {
			log.WarnContext(ctx, "objects were found again after deletion", slog.Int("pass", pass), slog.Int("objects", found))
		}
	}
	return nil, ErrLeftovers
}

// sweep lists every prefix, deletes what it finds in batches and returns how many objects it saw.
func (p *Purger) sweep(ctx context.Context, asset db.Asset, t *tally) (int, error) {
	found := 0
	for _, prefix := range keys.AssetPrefixes(asset.TenantID, asset.ID) {
		store := p.Source
		if prefix.Bucket == keys.Delivery {
			store = p.Delivery
		}
		type obj struct {
			class Class
			key   string
			size  int64
		}
		var batch []obj
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			ks := make([]string, len(batch))
			for i, o := range batch {
				ks[i] = o.key
			}
			if err := store.DeleteBatch(ctx, ks); err != nil {
				return storage.ToAppError(err)
			}
			for _, o := range batch {
				t.add(o.class, o.key, o.size)
			}
			batch = batch[:0]
			return nil
		}
		for o, err := range storage.ListAll(ctx, store, prefix.Prefix) {
			if err != nil {
				return found, storage.ToAppError(err)
			}
			found++
			batch = append(batch, obj{Classify(asset.TenantID, asset.ID, prefix.Bucket, o.Key), o.Key, o.Size})
			if len(batch) >= storage.MaxDeleteBatch {
				if err := flush(); err != nil {
					return found, err
				}
			}
		}
		if err := flush(); err != nil {
			return found, err
		}
	}
	return found, nil
}

// finish runs the database side of the purge in one transaction: the keys are destroyed (crypto
// shredding), the registry, the manifest and the upload bookkeeping go, the signed deletion record
// is stored and the asset becomes the tombstone. It runs only after storage was verified empty, so a failed purge leaves the keys
// where they are (the data stays encrypted) and a retry still knows which keys to name.
func (p *Purger) finish(ctx context.Context, asset db.Asset, t *tally, log *slog.Logger) error {
	var destroyed []db.DestroyedKey
	err := db.Tx(ctx, p.Pool, func(tx *db.Repos) error {
		cur, err := tx.LockAsset(ctx, asset.TenantID, asset.ID)
		if err != nil {
			return err
		}
		if cur.State == db.AssetDeleted {
			return nil // another job finished first
		}
		var root []byte
		switch m, merr := tx.GetManifest(ctx, asset.ID); {
		case merr == nil:
			root = m.TopRoot
		case !isNotFound(merr):
			return merr
		}
		if destroyed, err = p.Keys.DestroyAll(ctx, tx, asset.TenantID, asset.ID); err != nil {
			return err
		}
		if _, err := tx.DeleteAssetArtifacts(ctx, asset.ID); err != nil {
			return err
		}
		if _, err := tx.DeleteManifest(ctx, asset.ID); err != nil {
			return err
		}
		now := p.Now().UTC()
		rec, err := p.sealRecord(ctx, cur, t, destroyed, root, now)
		if err != nil {
			return err
		}
		if err := tx.InsertDeletionRecord(ctx, rec); err != nil {
			return err
		}
		if err := tx.DeleteUploadTokens(ctx, asset.ID); err != nil {
			return err
		}
		if err := tx.DeleteUploadParts(ctx, asset.ID); err != nil {
			return err
		}
		if _, err := tx.CompleteAssetDeletion(ctx, asset.TenantID, asset.ID, now); err != nil {
			return err
		}
		_, err = tx.InsertAuditEvent(ctx, db.NewAuditEvent{TenantID: asset.TenantID, Action: AuditAssetPurged, Target: asset.ID.String()})
		return err
	})
	if err != nil {
		return err
	}
	var objects, bytes int64
	for _, c := range t.classes {
		objects += c.Objects
		bytes += c.Bytes
	}
	log.InfoContext(ctx, "asset deleted", slog.Int64("objects", objects), slog.Int64("bytes", bytes), slog.Int("content_keys", len(destroyed)))
	return nil
}

func isNotFound(err error) bool {
	var e *errs.Error
	return errors.As(err, &e) && e.Code == errs.NotFound
}

// ActiveJobs reports whether a job of one of the kinds that names the asset is waiting, running or
// scheduled to retry. It reads River's table directly (the arguments are JSON with "asset_id").
func ActiveJobs(ctx context.Context, pool *pgxpool.Pool, asset id.AssetID, kinds ...string) (bool, error) {
	var active bool
	err := pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM river_job
		WHERE kind = ANY($1) AND args->>'asset_id' = $2
		  AND state IN ('available', 'pending', 'retryable', 'running', 'scheduled'))`,
		kinds, asset.String()).Scan(&active)
	if err != nil {
		return false, fmt.Errorf("purge: look for active jobs: %w", db.MapError(err))
	}
	return active, nil
}
