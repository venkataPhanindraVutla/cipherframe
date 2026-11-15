package branding

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Audit actions written by Service.
const (
	AuditLogoPut    = "brand.logo.put"
	AuditLogoUpdate = "brand.logo.update"
	AuditLogoDelete = "brand.logo.delete"
)

// DefaultCorner and DefaultOpacity apply to an upload that does not say.
const (
	DefaultCorner  = db.CornerBottomRight
	DefaultOpacity = 100
)

// ContentType is the media type of a stored logo.
const ContentType = "image/png"

// Deps are the collaborators of Service.
type Deps struct {
	Pool *pgxpool.Pool
	// Delivery is the delivery bucket, where logo versions are stored under keys.BrandLogoPrefix.
	Delivery storage.Store
	Log      *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service is the admin side of the brand logo. Every change runs in one transaction under the
// tenant's brand lock, which the pipeline also takes when it pins an asset to the current logo.
type Service struct {
	Deps
}

// New validates its arguments.
func New(d Deps) (*Service, error) {
	if d.Pool == nil || d.Delivery == nil {
		return nil, errors.New("branding: a pool and the delivery bucket are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &Service{Deps: d}, nil
}

// Placement is where and how strongly the logo is drawn. A nil field keeps the current value.
type Placement struct {
	Corner  *string
	Opacity *int
	Enabled *bool
}

func (p Placement) check() error {
	var bad []errs.FieldError
	if p.Corner != nil && !db.ValidCorner(*p.Corner) {
		bad = append(bad, errs.FieldError{Field: "corner", Message: "must be top_left, top_right, bottom_left or bottom_right"})
	}
	if p.Opacity != nil && (*p.Opacity < db.MinLogoOpacity || *p.Opacity > db.MaxLogoOpacity) {
		bad = append(bad, errs.FieldError{Field: "opacity", Message: "must be between 10 and 100"})
	}
	if len(bad) > 0 {
		return errs.Invalid("The logo placement is invalid.", bad)
	}
	return nil
}

// Put stores data (checked and re-encoded by Normalize) as a new version, makes it the tenant's
// current logo with the placement, and removes the versions nothing needs any more. Corner and
// opacity default to DefaultCorner and DefaultOpacity; Enabled defaults to true.
func (s *Service) Put(ctx context.Context, tenant id.TenantID, actor auth.Actor, data []byte, p Placement) (db.TenantLogo, error) {
	if err := p.check(); err != nil {
		return db.TenantLogo{}, err
	}
	norm, err := Normalize(data)
	if err != nil {
		return db.TenantLogo{}, err
	}
	corner, opacity, enabled := DefaultCorner, DefaultOpacity, true
	if p.Corner != nil {
		corner = *p.Corner
	}
	if p.Opacity != nil {
		opacity = *p.Opacity
	}
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	vid := id.New[id.LogoVersionKind]()
	key := keys.BrandLogo(tenant, vid)
	now := s.Now().UTC()

	stored := false
	err = s.inTx(ctx, func(tx *db.Repos) error {
		if err := tx.LockBrand(ctx, tenant); err != nil {
			return err
		}
		stored = true // from here on a failure removes the object
		if err := s.Delivery.Put(ctx, key, bytes.NewReader(norm.PNG), int64(len(norm.PNG)), ContentType); err != nil {
			return storage.ToAppError(err)
		}
		if err := tx.InsertLogoVersion(ctx, db.LogoVersion{
			ID: vid, TenantID: tenant, SHA256: norm.SHA256[:], SizeBytes: len(norm.PNG),
			Width: norm.Width, Height: norm.Height, CreatedAt: now,
		}); err != nil {
			return err
		}
		if err := tx.SetTenantLogo(ctx, tenant, vid, corner, opacity, enabled, now); err != nil {
			return err
		}
		if err := s.collect(ctx, tx, tenant); err != nil {
			return err
		}
		return audit(ctx, tx, tenant, actor, AuditLogoPut, vid.String())
	})
	if err != nil {
		if stored {
			s.removeObject(ctx, key)
		}
		return db.TenantLogo{}, err
	}
	return s.Get(ctx, tenant)
}

// Get returns the tenant's current logo, or not_found when it has none.
func (s *Service) Get(ctx context.Context, tenant id.TenantID) (db.TenantLogo, error) {
	l, err := db.New(s.Pool).GetTenantLogo(ctx, tenant)
	if err != nil {
		return db.TenantLogo{}, noLogo(err)
	}
	return l, nil
}

// Update changes the current logo's placement or enabled flag without a new upload. It affects only
// assets whose processing starts afterwards.
func (s *Service) Update(ctx context.Context, tenant id.TenantID, actor auth.Actor, p Placement) (db.TenantLogo, error) {
	if err := p.check(); err != nil {
		return db.TenantLogo{}, err
	}
	err := s.inTx(ctx, func(tx *db.Repos) error {
		if err := tx.LockBrand(ctx, tenant); err != nil {
			return err
		}
		cur, err := tx.GetTenantLogo(ctx, tenant)
		if err != nil {
			return noLogo(err)
		}
		if p.Corner != nil {
			cur.Corner = *p.Corner
		}
		if p.Opacity != nil {
			cur.OpacityPercent = *p.Opacity
		}
		if p.Enabled != nil {
			cur.Enabled = *p.Enabled
		}
		if err := tx.UpdateTenantLogoPlacement(ctx, tenant, cur.Corner, cur.OpacityPercent, cur.Enabled, s.Now().UTC()); err != nil {
			return err
		}
		return audit(ctx, tx, tenant, actor, AuditLogoUpdate, cur.ID.String())
	})
	if err != nil {
		return db.TenantLogo{}, err
	}
	return s.Get(ctx, tenant)
}

// Delete removes the tenant's logo setting and every stored version no asset in processing needs.
// Assets processed afterwards get no logo; finished assets are untouched.
func (s *Service) Delete(ctx context.Context, tenant id.TenantID, actor auth.Actor) error {
	return s.inTx(ctx, func(tx *db.Repos) error {
		if err := tx.LockBrand(ctx, tenant); err != nil {
			return err
		}
		cur, err := tx.GetTenantLogo(ctx, tenant)
		if err != nil {
			return noLogo(err)
		}
		if _, err := tx.DeleteTenantLogo(ctx, tenant); err != nil {
			return err
		}
		if err := s.collect(ctx, tx, tenant); err != nil {
			return err
		}
		return audit(ctx, tx, tenant, actor, AuditLogoDelete, cur.ID.String())
	})
}

// collect removes every version that is neither current nor still needed by an asset in processing
// (db.ListUnusedLogoVersions). Objects go first, then rows: a failure leaves the rows, and the next
// change finds them again. It runs under the brand lock, so a pin cannot pick a version up between
// the list and the delete.
func (s *Service) collect(ctx context.Context, tx *db.Repos, tenant id.TenantID) error {
	old, err := tx.ListUnusedLogoVersions(ctx, tenant)
	if err != nil || len(old) == 0 {
		return err
	}
	objects := make([]string, len(old))
	for i, v := range old {
		objects[i] = keys.BrandLogo(tenant, v)
	}
	if err := s.Delivery.DeleteBatch(ctx, objects); err != nil {
		return storage.ToAppError(err)
	}
	for _, v := range old {
		if err := tx.DeleteLogoVersion(ctx, tenant, v); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) removeObject(ctx context.Context, key string) {
	if err := s.Delivery.DeleteBatch(context.WithoutCancel(ctx), []string{key}); err != nil {
		s.Log.WarnContext(ctx, "could not remove a logo object after a failed change", slog.String("error", err.Error()))
	}
}

// noLogo says "no brand logo" for the not_found of a missing row.
func noLogo(err error) error {
	var e *errs.Error
	if errors.As(err, &e) && e.Code == errs.NotFound {
		return errs.New(errs.NotFound, "The tenant has no brand logo.")
	}
	return err
}

func audit(ctx context.Context, tx *db.Repos, tenant id.TenantID, actor auth.Actor, action, target string) error {
	_, err := tx.InsertAuditEvent(ctx, db.NewAuditEvent{
		TenantID: tenant, ClientID: actor.ClientID, APIKeyID: actor.KeyID,
		Action: action, Target: target, RequestID: actor.RequestID,
	})
	return err
}

func (s *Service) inTx(ctx context.Context, fn func(*db.Repos) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return db.MapError(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() // a no-op after Commit
	if err := fn(db.New(tx)); err != nil {
		return err
	}
	return db.MapError(tx.Commit(ctx))
}
