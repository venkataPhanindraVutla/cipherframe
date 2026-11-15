package subtitles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/anchor"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Audit actions written by Service (the audit_events.action column).
const (
	AuditSubtitleAdd    = "asset.subtitle.add"
	AuditSubtitleDelete = "asset.subtitle.delete"
)

// ContentType is the media type of a stored track.
const ContentType = "text/vtt; charset=utf-8"

// Enqueuer inserts a job in the caller's transaction. *jobs.Queue implements it.
type Enqueuer = anchor.Enqueuer

// Deps are the collaborators of Service.
type Deps struct {
	Pool *pgxpool.Pool
	// Delivery is the delivery bucket, where tracks are stored.
	Delivery storage.Store
	// Signer signs the manifest again after every change of the track list.
	Signer signing.Signer
	// Queue, when set, receives a manifest.anchor job with every manifest this service signs, like
	// the ones the pipeline stores (ADR 0041). Nil when timestamping is off.
	Queue Enqueuer
	Log   *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service adds, lists and removes the subtitle tracks of ready assets and keeps each asset's signed
// manifest in step (ADR 0044). Every change runs in one transaction under the asset row lock, so it
// cannot interleave with another change, with the masked variant's re-signing, or with the start of
// a deletion: an asset that is deleting accepts no track, and one that accepted a track has it
// registered before the purge looks.
type Service struct {
	Deps
}

// New validates its arguments.
func New(d Deps) (*Service, error) {
	if d.Pool == nil || d.Delivery == nil || d.Signer == nil {
		return nil, errors.New("subtitles: a pool, the delivery bucket and a signer are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &Service{Deps: d}, nil
}

// Meta is what the caller says about a new track.
type Meta struct {
	Language string
	Label    string
	Default  bool
}

// AddFile validates an uploaded WebVTT or SRT file and adds it as a track.
func (s *Service) AddFile(ctx context.Context, tenant id.TenantID, actor auth.Actor, asset id.AssetID, m Meta, data []byte) (db.Subtitle, error) {
	return s.add(ctx, tenant, actor, asset, m, db.SubtitleUpload, func(d time.Duration) (*Track, error) { return Parse(data, d) })
}

// AddTranscript validates imported timed text and adds it as a track (origin import).
func (s *Service) AddTranscript(ctx context.Context, tenant id.TenantID, actor auth.Actor, asset id.AssetID, m Meta, cues []TranscriptCue) (db.Subtitle, error) {
	return s.add(ctx, tenant, actor, asset, m, db.SubtitleImport, func(d time.Duration) (*Track, error) { return FromTranscript(cues, d) })
}

// invalid turns a Problem into a 400 with a field error, and passes other errors through.
func invalid(err error) error {
	var p *Problem
	if errors.As(err, &p) {
		return errs.Invalid("The request is invalid.", []errs.FieldError{{Field: p.Field, Message: p.Message}})
	}
	return err
}

// usable checks that an asset can take or lose tracks: ready, and not on its way out.
func usable(a db.Asset) error {
	switch a.State {
	case db.AssetReady:
		return nil
	case db.AssetDeleted:
		return errs.New(errs.NotFound, "No such asset.")
	case db.AssetDeleting:
		return errs.Wrap(errs.Conflict, "The asset is being deleted.", db.ErrStateChanged)
	}
	return errs.New(errs.AssetNotReady, "The asset is not ready.")
}

func (s *Service) add(ctx context.Context, tenant id.TenantID, actor auth.Actor, assetID id.AssetID, m Meta, origin string, build func(time.Duration) (*Track, error)) (db.Subtitle, error) {
	lang, err := NormalizeLanguage(m.Language)
	if err != nil {
		return db.Subtitle{}, invalid(err)
	}
	label, err := CleanLabel(m.Label)
	if err != nil {
		return db.Subtitle{}, invalid(err)
	}
	repos := db.New(s.Pool)
	// A first look, to refuse early and to know the duration the cues are checked against; the
	// state is checked again under the lock.
	asset, err := repos.GetAsset(ctx, tenant, assetID)
	if err != nil {
		return db.Subtitle{}, err
	}
	if err := usable(asset); err != nil {
		return db.Subtitle{}, err
	}
	track, err := build(time.Duration(asset.DurationMS) * time.Millisecond)
	if err != nil {
		return db.Subtitle{}, invalid(err)
	}
	vtt := track.WebVTT()
	sum := sha256.Sum256(vtt)
	trackID := id.New[id.SubtitleKind]()
	key := keys.Subtitle(tenant, assetID, trackID)

	var out db.Subtitle
	stored := false
	err = s.inTx(ctx, func(raw pgx.Tx, tx *db.Repos) error {
		cur, err := tx.LockAsset(ctx, tenant, assetID)
		if err != nil {
			return err
		}
		if err := usable(cur); err != nil {
			return err
		}
		existing, err := tx.ListSubtitles(ctx, tenant, assetID)
		if err != nil {
			return err
		}
		if len(existing) >= MaxTracks {
			return errs.New(errs.Conflict, "An asset has at most 20 subtitle tracks.")
		}
		stored = true // from here on a failure removes the object
		if err := s.Delivery.Put(ctx, key, bytes.NewReader(vtt), int64(len(vtt)), ContentType); err != nil {
			return storage.ToAppError(err)
		}
		if out, err = tx.InsertSubtitle(ctx, db.Subtitle{
			ID: trackID, AssetID: assetID, TenantID: tenant, Language: lang, Label: label, Default: m.Default, Origin: origin,
			CueCount: len(track.Cues), DurationMS: cur.DurationMS, SizeBytes: int64(len(vtt)), SHA256: sum[:], CreatedAt: s.Now().UTC(),
		}); err != nil {
			return err
		}
		if err := tx.RecordArtifact(ctx, db.Artifact{
			AssetID: assetID, Kind: db.ArtifactSubtitle, Bucket: string(keys.Delivery), ObjectKey: key,
			SizeBytes: int64(len(vtt)), SHA256: sum[:],
		}); err != nil {
			return err
		}
		if err := s.resign(ctx, raw, tx, tenant, assetID); err != nil {
			return err
		}
		return audit(ctx, tx, tenant, actor, AuditSubtitleAdd, assetID)
	})
	if err != nil {
		if stored {
			s.removeObject(ctx, key)
		}
		return db.Subtitle{}, err
	}
	return out, nil
}

// removeObject deletes an object that was written by a change that did not commit. A failure is
// logged without the key; the purge removes anything left when the asset is deleted.
func (s *Service) removeObject(ctx context.Context, key string) {
	if err := s.Delivery.DeleteBatch(context.WithoutCancel(ctx), []string{key}); err != nil {
		s.Log.WarnContext(ctx, "could not remove a subtitle object after a failed change", slog.String("error", err.Error()))
	}
}

// List returns the tracks of the tenant's asset, oldest first. A deleted asset has none to show.
func (s *Service) List(ctx context.Context, tenant id.TenantID, assetID id.AssetID) ([]db.Subtitle, error) {
	repos := db.New(s.Pool)
	asset, err := repos.GetAsset(ctx, tenant, assetID)
	if err != nil {
		return nil, err
	}
	if asset.State == db.AssetDeleted {
		return nil, errs.New(errs.NotFound, "No such asset.")
	}
	return repos.ListSubtitles(ctx, tenant, assetID)
}

// Get returns one track of the tenant's asset.
func (s *Service) Get(ctx context.Context, tenant id.TenantID, assetID id.AssetID, trackID id.SubtitleID) (db.Subtitle, error) {
	if _, err := s.List(ctx, tenant, assetID); err != nil {
		return db.Subtitle{}, err
	}
	return db.New(s.Pool).GetSubtitle(ctx, tenant, assetID, trackID)
}

// Delete removes a track: its object, its registry and metadata rows, and its entry in the signed
// manifest, which is signed again. The object goes first inside the transaction, so a failure
// leaves the track as it was and repeating the call finishes the job.
func (s *Service) Delete(ctx context.Context, tenant id.TenantID, actor auth.Actor, assetID id.AssetID, trackID id.SubtitleID) error {
	key := keys.Subtitle(tenant, assetID, trackID)
	return s.inTx(ctx, func(raw pgx.Tx, tx *db.Repos) error {
		cur, err := tx.LockAsset(ctx, tenant, assetID)
		if err != nil {
			return err
		}
		if err := usable(cur); err != nil {
			return err
		}
		if _, err := tx.GetSubtitle(ctx, tenant, assetID, trackID); err != nil {
			return err
		}
		if err := s.Delivery.DeleteBatch(ctx, []string{key}); err != nil {
			return storage.ToAppError(err)
		}
		if _, err := tx.DeleteSubtitle(ctx, tenant, assetID, trackID); err != nil {
			return err
		}
		if err := tx.DeleteArtifact(ctx, assetID, string(keys.Delivery), key); err != nil {
			return err
		}
		if err := s.resign(ctx, raw, tx, tenant, assetID); err != nil {
			return err
		}
		return audit(ctx, tx, tenant, actor, AuditSubtitleDelete, assetID)
	})
}

// resign rebuilds the asset's manifest with its current track list and stores it in place of the
// old one, in the caller's transaction. The new payload is queued for timestamping when that is on.
func (s *Service) resign(ctx context.Context, raw pgx.Tx, tx *db.Repos, tenant id.TenantID, assetID id.AssetID) error {
	cur, err := tx.GetManifest(ctx, assetID)
	if err != nil {
		return err
	}
	m, err := pipeline.DecodeManifest(cur.Envelope)
	if err != nil {
		return err
	}
	tracks, err := tx.ListSubtitles(ctx, tenant, assetID)
	if err != nil {
		return err
	}
	prefix := keys.DeliveryPrefix(tenant, assetID)
	inputs := make([]manifest.SubtitleInput, len(tracks))
	for i, t := range tracks {
		in := manifest.SubtitleInput{
			ID: t.ID.String(), Language: t.Language, Default: t.Default, Origin: t.Origin,
			Object: manifest.StoredObject{Path: strings.TrimPrefix(keys.Subtitle(tenant, assetID, t.ID), prefix), Size: t.SizeBytes},
		}
		copy(in.Object.SHA256[:], t.SHA256)
		inputs[i] = in
	}
	built, err := manifest.WithSubtitles(m, inputs)
	if err != nil {
		return err
	}
	row, err := pipeline.SignManifest(ctx, s.Signer, tenant, assetID, built, s.Now().UTC())
	if err != nil {
		return err
	}
	if err := tx.ReplaceManifest(ctx, *row, cur.PayloadSHA256); err != nil {
		return err
	}
	if s.Queue == nil {
		return nil
	}
	return anchor.Enqueue(ctx, s.Queue, raw, tenant, assetID, row.PayloadSHA256)
}

func audit(ctx context.Context, tx *db.Repos, tenant id.TenantID, actor auth.Actor, action string, assetID id.AssetID) error {
	_, err := tx.InsertAuditEvent(ctx, db.NewAuditEvent{
		TenantID: tenant, ClientID: actor.ClientID, APIKeyID: actor.KeyID,
		Action: action, Target: assetID.String(), RequestID: actor.RequestID,
	})
	return err
}

// inTx runs fn in a transaction, handing it the raw transaction too (the anchor job is inserted
// with it).
func (s *Service) inTx(ctx context.Context, fn func(pgx.Tx, *db.Repos) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return db.MapError(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() // a no-op after Commit
	if err := fn(tx, db.New(tx)); err != nil {
		return err
	}
	return db.MapError(tx.Commit(ctx))
}
