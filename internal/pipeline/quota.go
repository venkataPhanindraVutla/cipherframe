package pipeline

import (
	"context"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// TranscodeCharger records the source minutes an asset uses (quota.Service implements it). It
// returns quota_exceeded when the charge would pass a limit, and charges an asset once however
// often the job retries.
type TranscodeCharger interface {
	ChargeTranscode(ctx context.Context, tenant id.TenantID, asset id.AssetID, d time.Duration) error
}

// chargeQuota charges the probed duration. A quota refusal fails the asset for good with
// FailureQuotaTranscode: waiting does not help until the month turns or the limit is raised, and
// the client sees the failure on the asset (and in asset.failed) instead of a stuck job.
func (p *Processor) chargeQuota(ctx context.Context, asset db.Asset, d time.Duration) error {
	if p.Quota == nil {
		return nil
	}
	err := p.Quota.ChargeTranscode(ctx, asset.TenantID, asset.ID, d)
	if isCode(err, errs.QuotaExceeded) {
		return permanent(FailureQuotaTranscode, err)
	}
	return err
}
