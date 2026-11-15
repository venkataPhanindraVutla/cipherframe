package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

type fakeCharger struct {
	err error
	got time.Duration
}

func (f *fakeCharger) ChargeTranscode(_ context.Context, _ id.TenantID, _ id.AssetID, d time.Duration) error {
	f.got = d
	return f.err
}

func TestChargeQuota(t *testing.T) {
	ctx := context.Background()

	// No charger, no charge.
	if err := (&Processor{}).chargeQuota(ctx, db.Asset{}, time.Minute); err != nil {
		t.Fatalf("nil quota: %v", err)
	}

	ok := &fakeCharger{}
	if err := (&Processor{Deps: Deps{Quota: ok}}).chargeQuota(ctx, db.Asset{}, 90*time.Second); err != nil || ok.got != 90*time.Second {
		t.Fatalf("charge: err=%v got=%v", err, ok.got)
	}

	// A refusal fails the asset for good with the stable code, and shows as quota_exceeded in the
	// dead-letter list.
	refused := &fakeCharger{err: errs.Quota("transcode_minutes_per_month", "used up")}
	err := (&Processor{Deps: Deps{Quota: refused}}).chargeQuota(ctx, db.Asset{}, time.Minute)
	var perm *permanentError
	if !errors.As(err, &perm) || perm.code != FailureQuotaTranscode || perm.errsCode() != errs.QuotaExceeded {
		t.Fatalf("refusal = %v", err)
	}
	if FailureQuotaTranscode != "quota_transcode_minutes" {
		t.Fatalf("the failure code is part of the API: %q", FailureQuotaTranscode)
	}

	// Anything else (a database blip) is retried, not a failure of the asset.
	boom := errors.New("database down")
	err = (&Processor{Deps: Deps{Quota: &fakeCharger{err: boom}}}).chargeQuota(ctx, db.Asset{}, time.Minute)
	if !errors.Is(err, boom) || errors.As(err, &perm) {
		t.Fatalf("transient error = %v", err)
	}
}
