package rekey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/anchor"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/purge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

const (
	// jobTimeout bounds one run: it reads and writes every segment of the asset once.
	jobTimeout = 4 * time.Hour
	// maxAttempts is the attempt limit. A retry starts the work again from the staging cleanup.
	maxAttempts = 5
	// maxObjectBytes bounds what is read into memory for one object: a segment is a few seconds of
	// video, far below this.
	maxObjectBytes = 1 << 30

	typeSegment  = "application/octet-stream"
	typePlaylist = "application/vnd.apple.mpegurl"
)

// Deps are the collaborators of the Processor.
type Deps struct {
	Pool     *pgxpool.Pool
	Delivery storage.Store
	Keys     *contentkey.Manager
	Signer   signing.Signer
	// Queue receives the jobs queued with the switch. It may be nil when neither Anchor nor CDN is set.
	Queue Enqueuer
	// Anchor queues a manifest.anchor job for the new manifest (ADR 0041); set when a TSA is configured.
	Anchor bool
	// CDN queues the asset's CDN purge (ADR 0062); set when a CDN is configured.
	CDN bool
	Log *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// Processor runs asset.rekey jobs.
type Processor struct{ Deps }

// New validates deps and returns a Processor.
func New(d Deps) (*Processor, error) {
	switch {
	case d.Pool == nil || d.Delivery == nil || d.Keys == nil || d.Signer == nil:
		return nil, errors.New("rekey: a pool, the delivery bucket, the key service and a signer are required")
	case (d.Anchor || d.CDN) && d.Queue == nil:
		return nil, errors.New("rekey: a job queue is required to anchor or purge")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Processor{Deps: d}, nil
}

// Register registers asset.rekey on the default queue. Only the worker role calls it.
func Register(reg *jobs.Registry, d Deps) error {
	p, err := New(d)
	if err != nil {
		return err
	}
	return jobs.Register(reg, p.Handle, jobs.KindConfig{Timeout: jobTimeout, MaxAttempts: maxAttempts})
}

// Declare tells a process that only inserts jobs how asset.rekey is configured.
func Declare(reg *jobs.Registry) error {
	return jobs.Declare[Args](reg, jobs.KindConfig{MaxAttempts: maxAttempts})
}

// errAssetGone means the asset left the ready state (it is being deleted): the job stops and
// removes what it staged.
var errAssetGone = errors.New("rekey: the asset is no longer ready")

// permanentError marks a failure no retry can fix: a stored object that does not match what was
// signed, or does not decrypt.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return "rekey: " + e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// Handle works one asset.rekey job. It is idempotent: it starts by removing whatever an earlier
// attempt staged, and a run that finds the switch already made only removes the old objects.
func (p *Processor) Handle(ctx context.Context, job jobs.Job[Args]) error {
	a := job.Args
	if a.TenantID.IsZero() || a.AssetID.IsZero() || a.FromGeneration < 0 {
		return jobs.Cancel(errs.New(errs.InvalidRequest, "the job has no asset"))
	}
	log := p.Log.With(slog.String("job", JobKind), slog.String("tenant_id", a.TenantID.String()),
		slog.String("asset_id", a.AssetID.String()), slog.Int("attempt", job.Attempt))

	asset, err := db.New(p.Pool).GetAsset(ctx, a.TenantID, a.AssetID)
	if err != nil {
		if isCode(err, errs.NotFound) {
			return jobs.Cancel(err)
		}
		return err
	}
	switch {
	case asset.State != db.AssetReady:
		log.InfoContext(ctx, "nothing to do: the asset is no longer ready", slog.String("state", string(asset.State)))
		return nil
	case asset.KeyGeneration > a.FromGeneration:
		log.InfoContext(ctx, "the switch was already made; removing the old objects")
		return p.removeOld(ctx, asset, a.FromGeneration)
	case asset.KeyGeneration < a.FromGeneration:
		return jobs.Cancel(errs.New(errs.Conflict, "the asset is at an older key generation than requested"))
	}

	start := p.Now()
	err = p.run(ctx, a, asset, log)
	if err == nil {
		log.InfoContext(ctx, "asset re-keyed", slog.Int("generation", a.FromGeneration+1), slog.Duration("elapsed", p.Now().Sub(start)))
		return nil
	}
	return p.handleFailure(ctx, job, asset, err, log)
}

// handleFailure decides what a failed run means for the asset and for the job.
func (p *Processor) handleFailure(ctx context.Context, job jobs.Job[Args], asset db.Asset, err error, log *slog.Logger) error {
	bg := context.WithoutCancel(ctx)
	next := job.Args.FromGeneration + 1
	var perm *permanentError
	switch {
	case errors.Is(err, errAssetGone):
		log.InfoContext(ctx, "the asset is no longer ready; stopping")
		return p.cleanStaging(bg, asset, next)
	case ctx.Err() != nil:
		log.WarnContext(ctx, "re-key interrupted")
		return err
	case errors.As(err, &perm):
		log.ErrorContext(ctx, "re-key failed for good", slog.String("error", err.Error()))
		if ferr := p.fail(bg, asset, next); ferr != nil {
			return ferr
		}
		return jobs.Cancel(errs.New(errs.InternalError, "re-key failed"))
	case job.Attempt >= job.MaxAttempts:
		log.ErrorContext(ctx, "re-key failed on the last attempt", slog.String("error", err.Error()))
		if ferr := p.fail(bg, asset, next); ferr != nil {
			return ferr
		}
		return err
	}
	log.WarnContext(ctx, "re-key failed, will retry", slog.String("error", err.Error()))
	return err
}

// fail removes the staged objects and records the failure in the audit log. The asset is untouched:
// it still plays under its old key.
func (p *Processor) fail(ctx context.Context, asset db.Asset, next int) error {
	if err := p.cleanStaging(ctx, asset, next); err != nil {
		p.Log.WarnContext(ctx, "could not remove the staged objects", slog.String("error", err.Error()))
	}
	_, err := db.New(p.Pool).InsertAuditEvent(ctx, db.NewAuditEvent{TenantID: asset.TenantID, Action: AuditFailed, Target: asset.ID.String()})
	return err
}

// stagedVariant is one variant's re-encrypted objects, waiting for the switch.
type stagedVariant struct {
	variant keys.Variant
	oldKey  id.ContentKeyID     // the key the variant has now
	newKey  db.NewContentKeyRow // the key it gets at the switch, wrapped
	rekeyed manifest.Rekeyed
	roots   map[string]string // each rendition's signed Merkle root when staging began
	arts    []db.Artifact     // the new objects, to register at the switch
	gone    []string          // the old objects' keys, to unregister at the switch
}

// run stages every variant, then switches the asset over.
func (p *Processor) run(ctx context.Context, a Args, asset db.Asset, log *slog.Logger) error {
	next := a.FromGeneration + 1
	if err := p.cleanStaging(ctx, asset, next); err != nil {
		return err
	}
	cur, err := db.New(p.Pool).GetManifest(ctx, asset.ID)
	if err != nil {
		return err
	}
	m, err := pipeline.DecodeManifest(cur.Envelope)
	if err != nil {
		return err
	}
	var staged []stagedVariant
	st, err := p.stage(ctx, asset, keys.Original, m.Renditions, m.Artifacts, next, log)
	if err != nil {
		return err
	}
	staged = append(staged, st)
	if m.Masked != nil {
		st, err := p.stage(ctx, asset, keys.Masked, m.Masked.Renditions, m.Masked.Artifacts, next, log)
		if err != nil {
			return err
		}
		staged = append(staged, st)
	}
	if err := p.switchOver(ctx, a, asset, staged); err != nil {
		return err
	}
	return p.removeOld(ctx, asset, a.FromGeneration)
}

// stage re-encrypts every segment of one variant under a fresh key into generation next, and writes
// the playlists that carry the new IVs. Everything it needs comes from the signed manifest: the
// segments in playlist order, their hashes (checked before use) and the playlists' paths. Nothing is
// registered or switched here: the asset keeps playing under its old key.
func (p *Processor) stage(ctx context.Context, asset db.Asset, variant keys.Variant, renditions []manifest.Rendition, artifacts []manifest.Artifact, next int, log *slog.Logger) (stagedVariant, error) {
	oldKey, err := p.Keys.Get(ctx, asset.TenantID, asset.ID, variant)
	if err != nil {
		return stagedVariant{}, err
	}
	defer oldKey.Zero()
	newKey, row, err := p.Keys.Generate(ctx, asset.ID, variant)
	if err != nil {
		return stagedVariant{}, err
	}
	defer newKey.Zero()
	oldBytes, newBytes := oldKey.Bytes(), newKey.Bytes()
	defer clear(oldBytes)
	defer clear(newBytes)

	prefix := keys.VariantHLSPrefix(asset.TenantID, asset.ID, variant)
	st := stagedVariant{
		variant: variant, oldKey: oldKey.ID(), newKey: row, roots: map[string]string{},
		rekeyed: manifest.Rekeyed{Segments: map[string][]manifest.StoredObject{}, Playlists: map[string]manifest.StoredObject{}},
	}
	playlists := map[string]string{}
	for _, a := range artifacts {
		if a.Kind == manifest.KindPlaylist {
			playlists[a.Rendition] = a.Path
		}
	}
	put := func(kind db.ArtifactKind, rendition, rel, contentType string, body []byte) (manifest.StoredObject, error) {
		sum := sha256.Sum256(body)
		key := prefix + rel
		if err := p.Delivery.Put(ctx, key, bytes.NewReader(body), int64(len(body)), contentType); err != nil {
			return manifest.StoredObject{}, fmt.Errorf("rekey: upload: %w", err)
		}
		st.arts = append(st.arts, db.Artifact{
			AssetID: asset.ID, Kind: kind, Rendition: rendition, Bucket: string(keys.Delivery),
			ObjectKey: key, SizeBytes: int64(len(body)), SHA256: sum[:], Variant: variant.String(),
		})
		return manifest.StoredObject{Path: rel, SHA256: sum, Size: int64(len(body))}, nil
	}

	segments := 0
	for _, r := range renditions {
		plPath, ok := playlists[r.Name]
		if !ok {
			return st, permanent("the manifest names no playlist for a rendition")
		}
		text, err := p.read(ctx, prefix+plPath)
		if err != nil {
			return st, err
		}
		pl, err := hls.ParseMedia(string(text))
		if err != nil || len(pl.Segments) != len(r.Segments) {
			return st, permanent("a stored playlist does not match the manifest")
		}
		st.roots[r.Name] = r.MerkleRoot
		st.gone = append(st.gone, prefix+plPath)
		out := make([]manifest.StoredObject, len(r.Segments))
		for i, seg := range r.Segments {
			ct, err := p.read(ctx, prefix+seg.Path)
			if err != nil {
				return st, err
			}
			if sum := sha256.Sum256(ct); hex.EncodeToString(sum[:]) != seg.SHA256 {
				return st, permanent("a stored segment does not match the signed manifest")
			}
			plain, err := hls.DecryptSegment(oldBytes, pl.Segments[i].IV, ct)
			if err != nil {
				return st, permanent("a stored segment does not decrypt")
			}
			iv, err := hls.NewIV()
			if err != nil {
				clear(plain)
				return st, err
			}
			fresh, err := hls.EncryptSegment(newBytes, iv, plain)
			clear(plain)
			if err != nil {
				return st, err
			}
			if out[i], err = put(db.ArtifactSegment, r.Name, keys.WithGeneration(seg.Path, next), typeSegment, fresh); err != nil {
				return st, err
			}
			pl.Segments[i].IV = iv
			st.gone = append(st.gone, prefix+seg.Path)
			segments++
		}
		rendered, err := hls.RenderMedia(pl)
		if err != nil {
			return st, err
		}
		if st.rekeyed.Playlists[r.Name], err = put(db.ArtifactPlaylist, r.Name, keys.WithGeneration(plPath, next), typePlaylist, []byte(rendered)); err != nil {
			return st, err
		}
		st.rekeyed.Segments[r.Name] = out
	}
	log.InfoContext(ctx, "variant re-encrypted", slog.String("variant", variant.String()), slog.Int("segments", segments))
	return st, nil
}

// read reads one stored object into memory, refusing one over maxObjectBytes.
func (p *Processor) read(ctx context.Context, key string) ([]byte, error) {
	rc, info, err := p.Delivery.Get(ctx, key, nil)
	if err != nil {
		return nil, storage.ToAppError(err)
	}
	defer func() { _ = rc.Close() }()
	if info.Size > maxObjectBytes {
		return nil, permanent("a stored object is larger than a segment can be")
	}
	b, err := io.ReadAll(io.LimitReader(rc, maxObjectBytes+1))
	if err != nil {
		return nil, storage.ToAppError(storage.Sanitize("get", keys.Delivery, err))
	}
	return b, nil
}

// switchOver makes the new key the asset's key. In one transaction, under the asset lock, it signs
// the manifest again, replaces the content keys (the old rows are destroyed), registers the new
// objects and unregisters the old ones, moves the asset to the next generation and queues the
// timestamp anchor and the CDN purge. A crash or error before the commit changes nothing.
func (p *Processor) switchOver(ctx context.Context, a Args, asset db.Asset, staged []stagedVariant) error {
	// Signing inside the transaction must not need a second pool connection (see signing.Prepare).
	signer, release, err := signing.Prepare(ctx, p.Signer)
	if err != nil {
		return err
	}
	defer release()

	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return db.MapError(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() // a no-op after Commit
	repos := db.New(tx)

	cur, err := repos.LockAsset(ctx, asset.TenantID, asset.ID)
	if err != nil {
		return err
	}
	if cur.State != db.AssetReady {
		return errAssetGone
	}
	if cur.KeyGeneration != a.FromGeneration {
		return errs.New(errs.Conflict, "the asset changed key generation during the re-key")
	}
	stored, err := repos.GetManifest(ctx, asset.ID)
	if err != nil {
		return err
	}
	m, err := pipeline.DecodeManifest(stored.Envelope)
	if err != nil {
		return err
	}
	// Subtitle changes re-sign the manifest under this same lock and leave the renditions alone;
	// anything else that changed them means what was staged is stale, and the retry stages again.
	if !sameRoots(m.Renditions, staged[0].roots) || (m.Masked != nil) != (len(staged) == 2) ||
		(m.Masked != nil && !sameRoots(m.Masked.Renditions, staged[1].roots)) {
		return errors.New("rekey: the manifest changed while the segments were re-encrypted")
	}
	var masked *manifest.Rekeyed
	if len(staged) == 2 {
		masked = &staged[1].rekeyed
	}
	built, err := manifest.WithRekeyed(m, staged[0].rekeyed, masked)
	if err != nil {
		return err
	}
	now := p.Now().UTC()
	row, err := pipeline.SignManifest(ctx, signer, asset.TenantID, asset.ID, built, now)
	if err != nil {
		return err
	}
	if err := repos.ReplaceManifest(ctx, *row, stored.PayloadSHA256); err != nil {
		return err
	}
	for _, st := range staged {
		if err := repos.SwapContentKey(ctx, asset.TenantID, st.oldKey, st.newKey); err != nil {
			return err
		}
		for _, key := range st.gone {
			if err := repos.DeleteArtifact(ctx, asset.ID, string(keys.Delivery), key); err != nil {
				return err
			}
		}
		for _, art := range st.arts {
			if err := repos.RecordArtifact(ctx, art); err != nil {
				return err
			}
		}
	}
	if err := repos.SetKeyGeneration(ctx, asset.TenantID, asset.ID, a.FromGeneration, now); err != nil {
		return err
	}
	if p.Anchor {
		if err := anchor.Enqueue(ctx, p.Queue, tx, asset.TenantID, asset.ID, row.PayloadSHA256); err != nil {
			return err
		}
	}
	if p.CDN {
		if _, err := p.Queue.Enqueue(ctx, tx, purge.CDNArgs{TenantID: asset.TenantID, AssetID: asset.ID}, nil); err != nil {
			return err
		}
	}
	if _, err := repos.InsertAuditEvent(ctx, db.NewAuditEvent{TenantID: asset.TenantID, Action: AuditCompleted, Target: asset.ID.String()}); err != nil {
		return err
	}
	return db.MapError(tx.Commit(ctx))
}

func sameRoots(renditions []manifest.Rendition, roots map[string]string) bool {
	if len(renditions) != len(roots) {
		return false
	}
	for _, r := range renditions {
		if roots[r.Name] != r.MerkleRoot {
			return false
		}
	}
	return true
}

// cleanStaging removes every object of generation next of both variants: nothing there is
// registered or referenced before the switch, so whatever is found is an earlier attempt's.
func (p *Processor) cleanStaging(ctx context.Context, asset db.Asset, next int) error {
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		prefix := keys.VariantGenPrefix(asset.TenantID, asset.ID, v, next)
		if err := p.deleteWhere(ctx, prefix, func(string) bool { return true }); err != nil {
			return err
		}
	}
	return nil
}

// removeOld deletes the encrypted objects (segments and media playlists) of key generation from,
// which the switch left behind. The init segment, master playlist and thumbnails are shared by every
// generation and stay. It is idempotent and keys the listing, not the registry, so a run after a
// crash finds the same objects.
func (p *Processor) removeOld(ctx context.Context, asset db.Asset, from int) error {
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		prefix := keys.VariantHLSPrefix(asset.TenantID, asset.ID, v)
		err := p.deleteWhere(ctx, prefix, func(key string) bool {
			c := purge.Classify(asset.TenantID, asset.ID, keys.Delivery, key)
			gen, _ := keys.SplitGeneration(key[len(prefix):])
			return gen == from && (c.Kind == purge.KindSegment || c.Kind == purge.KindPlaylist)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// deleteWhere deletes the objects under prefix for which match is true.
func (p *Processor) deleteWhere(ctx context.Context, prefix string, match func(key string) bool) error {
	var batch []string
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := p.Delivery.DeleteBatch(ctx, batch)
		batch = batch[:0]
		return err
	}
	for obj, err := range storage.ListAll(ctx, p.Delivery, prefix) {
		if err != nil {
			return fmt.Errorf("rekey: list delivery objects: %w", err)
		}
		if !match(obj.Key) {
			continue
		}
		batch = append(batch, obj.Key)
		if len(batch) >= storage.MaxDeleteBatch {
			if err := flush(); err != nil {
				return fmt.Errorf("rekey: delete delivery objects: %w", err)
			}
		}
	}
	if err := flush(); err != nil {
		return fmt.Errorf("rekey: delete delivery objects: %w", err)
	}
	return nil
}

func permanent(what string) error { return &permanentError{err: errors.New(what)} }

func isCode(err error, code errs.Code) bool {
	var e *errs.Error
	return errors.As(err, &e) && e.Code == code
}
