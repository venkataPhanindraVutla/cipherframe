package purge

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/cdn"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// CDNJobKind is the River job kind of the CDN purge (ADR 0062, 0065). Do not rename it once jobs of
// that kind exist.
const CDNJobKind = "asset.cdn_purge"

// Audit actions of the CDN purge.
const (
	AuditCDNPurged      = "asset.cdn_purged"       // the CDN accepted the purge of the asset's prefix
	AuditCDNPurgeFailed = "asset.cdn_purge_failed" // every attempt failed; cached ciphertext expires on its own
)

// CDNArgs are the arguments of the asset.cdn_purge job: identifiers only.
type CDNArgs struct {
	TenantID id.TenantID `json:"tenant_id"`
	AssetID  id.AssetID  `json:"asset_id"`
}

// Kind implements jobs.Args.
func (CDNArgs) Kind() string { return CDNJobKind }

const (
	cdnJobTimeout     = 2 * time.Minute
	cdnJobMaxAttempts = 10
)

// CDNDeps are the collaborators of the CDN purge job.
type CDNDeps struct {
	Pool   *pgxpool.Pool
	Purger cdn.Purger
	Log    *slog.Logger
}

// RegisterCDN registers asset.cdn_purge on the default queue.
func RegisterCDN(reg *jobs.Registry, d CDNDeps) error {
	if d.Pool == nil || d.Purger == nil {
		return errors.New("purge: a pool and a CDN purger are required")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return jobs.Register(reg, d.handle, jobs.KindConfig{Timeout: cdnJobTimeout, MaxAttempts: cdnJobMaxAttempts})
}

// DeclareCDN tells a process that only inserts jobs how asset.cdn_purge is configured.
func DeclareCDN(reg *jobs.Registry) error {
	return jobs.Declare[CDNArgs](reg, jobs.KindConfig{MaxAttempts: cdnJobMaxAttempts})
}

// handle purges the asset's delivery prefix from the CDN and records the outcome in the audit log.
// It is idempotent: the provider calls accept a repeat. Only the last failed attempt writes the
// failure, so a retried job leaves one audit row.
func (d CDNDeps) handle(ctx context.Context, job jobs.Job[CDNArgs]) error {
	tenant, asset := job.Args.TenantID, job.Args.AssetID
	if tenant.IsZero() || asset.IsZero() {
		return jobs.Cancel(errs.New(errs.InvalidRequest, "the job has no asset"))
	}
	log := d.Log.With(slog.String("job", CDNJobKind), slog.String("tenant_id", tenant.String()),
		slog.String("asset_id", asset.String()), slog.Int("attempt", job.Attempt))
	repos := db.New(d.Pool)
	if err := d.Purger.Purge(ctx, keys.DeliveryPrefix(tenant, asset)); err != nil {
		log.WarnContext(ctx, "CDN purge failed", slog.String("error", err.Error()))
		if job.Attempt >= job.MaxAttempts {
			if _, aerr := repos.InsertAuditEvent(context.WithoutCancel(ctx), db.NewAuditEvent{TenantID: tenant, Action: AuditCDNPurgeFailed, Target: asset.String()}); aerr != nil {
				return aerr
			}
		}
		return err
	}
	if _, err := repos.InsertAuditEvent(ctx, db.NewAuditEvent{TenantID: tenant, Action: AuditCDNPurged, Target: asset.String()}); err != nil {
		return err
	}
	log.InfoContext(ctx, "CDN purge accepted")
	return nil
}
