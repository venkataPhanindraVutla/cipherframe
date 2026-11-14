package retention

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

func ptr[T any](v T) *T { return &v }

func TestResolveExpiry(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 123456789, time.UTC)
	cases := map[string]struct {
		expiresAt *time.Time
		ttl       *int
		want      *time.Time // nil: no expiry
		field     string     // the invalid field, "" when valid
	}{
		"neither":            {},
		"ttl":                {ttl: ptr(3600), want: ptr(time.Date(2026, 11, 14, 11, 0, 0, 123456000, time.UTC))},
		"ttl minimum":        {ttl: ptr(60), want: ptr(time.Date(2026, 11, 14, 10, 1, 0, 123456000, time.UTC))},
		"ttl too small":      {ttl: ptr(59), field: "ttl_seconds"},
		"ttl negative":       {ttl: ptr(-5), field: "ttl_seconds"},
		"ttl too large":      {ttl: ptr(db.MaxAssetTTLSeconds + 1), field: "ttl_seconds"},
		"expires_at":         {expiresAt: ptr(now.Add(48 * time.Hour)), want: ptr(now.Add(48 * time.Hour).Truncate(time.Microsecond))},
		"expires_at in zone": {expiresAt: ptr(now.Add(time.Hour).In(time.FixedZone("x", 3600))), want: ptr(now.Add(time.Hour).Truncate(time.Microsecond))},
		"expires_at past":    {expiresAt: ptr(now.Add(-time.Hour)), field: "expires_at"},
		"expires_at soon":    {expiresAt: ptr(now.Add(30 * time.Second)), field: "expires_at"},
		"expires_at far":     {expiresAt: ptr(now.Add(MaxLead + time.Hour)), field: "expires_at"},
		"both":               {expiresAt: ptr(now.Add(time.Hour)), ttl: ptr(3600), field: "ttl_seconds"},
	}
	for name, c := range cases {
		got, err := ResolveExpiry(now, c.expiresAt, c.ttl)
		if c.field != "" {
			var e *errs.Error
			if !errors.As(err, &e) || e.Code != errs.InvalidRequest || len(e.Fields) != 1 || e.Fields[0].Field != c.field {
				t.Errorf("%s: error = %v, want invalid_request on %s", name, err, c.field)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		switch {
		case c.want == nil && got != nil, c.want != nil && (got == nil || !got.Equal(*c.want)):
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		case got != nil && got.Location() != time.UTC:
			t.Errorf("%s: %v is not in UTC", name, got.Location())
		}
	}
}

type fakeStore struct {
	expired    []db.Asset // what ListExpiredAssets returns until requested
	listErr    error
	dropErr    error
	dropped    []string
	dropBefore time.Time
	accessRows int64 // rows still to delete
	eventRows  int64
	cutoffs    []time.Time
	delErr     error
}

func (f *fakeStore) ListExpiredAssets(_ context.Context, _ time.Time, limit int) ([]db.Asset, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.expired[:min(limit, len(f.expired))], nil
}

func (f *fakeStore) DropAccessLogPartitionsBefore(_ context.Context, before time.Time) ([]string, error) {
	f.dropBefore = before
	return f.dropped, f.dropErr
}

func (f *fakeStore) del(left *int64, cutoff time.Time, batch int) (int64, error) {
	f.cutoffs = append(f.cutoffs, cutoff)
	if f.delErr != nil {
		return 0, f.delErr
	}
	n := min(*left, int64(batch))
	*left -= n
	return n, nil
}

func (f *fakeStore) DeleteAccessLogBefore(_ context.Context, cutoff time.Time, batch int) (int64, error) {
	return f.del(&f.accessRows, cutoff, batch)
}

func (f *fakeStore) DeletePlaybackEventsBefore(_ context.Context, cutoff time.Time, batch int) (int64, error) {
	return f.del(&f.eventRows, cutoff, batch)
}

type fakeRequester struct {
	store  *fakeStore
	reason []string
	failOn id.AssetID
}

func (r *fakeRequester) Request(_ context.Context, tenant id.TenantID, asset id.AssetID, reason string, actor *auth.Actor) (db.Asset, error) {
	if actor != nil {
		panic("the retention job has no actor")
	}
	if asset == r.failOn {
		return db.Asset{}, errors.New("queue down")
	}
	r.reason = append(r.reason, reason)
	// A deleting asset leaves the work list.
	for i, a := range r.store.expired {
		if a.ID == asset {
			r.store.expired = append(r.store.expired[:i], r.store.expired[i+1:]...)
			break
		}
	}
	return db.Asset{ID: asset, TenantID: tenant}, nil
}

func newAsset() db.Asset {
	return db.Asset{ID: id.New[id.AssetKind](), TenantID: id.New[id.TenantKind]()}
}

func TestSweepQueuesExpiredAssetsAndTrimsTheTrail(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	st := &fakeStore{expired: []db.Asset{newAsset(), newAsset(), newAsset()}, dropped: []string{"playback_access_log_p202601"}, accessRows: 12000, eventRows: 7}
	rq := &fakeRequester{store: st}
	s := &Sweeper{Store: st, Requester: rq, AccessLogDays: 90, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now }}
	res, err := s.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExpiredAssets != 3 || len(rq.reason) != 3 || rq.reason[0] != db.DeletionRetention {
		t.Errorf("result = %+v, reasons %v", res, rq.reason)
	}
	wantCutoff := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	if !st.dropBefore.Equal(wantCutoff) {
		t.Errorf("partitions dropped before %v, want %v", st.dropBefore, wantCutoff)
	}
	for _, c := range st.cutoffs {
		if !c.Equal(wantCutoff) {
			t.Errorf("rows deleted before %v, want %v", c, wantCutoff)
		}
	}
	if res.AccessLogRows != 12000 || res.EventRows != 7 || len(res.DroppedPartitions) != 1 {
		t.Errorf("result = %+v", res)
	}
}

func TestSweepKeepsGoingAfterAFailure(t *testing.T) {
	bad, good := newAsset(), newAsset()
	st := &fakeStore{expired: []db.Asset{bad, good}, dropErr: errors.New("no privilege"), accessRows: 3}
	rq := &fakeRequester{store: st, failOn: bad.ID}
	s := &Sweeper{Store: st, Requester: rq, AccessLogDays: 30, Log: slog.New(slog.DiscardHandler)}
	res, err := s.Sweep(context.Background())
	if err == nil {
		t.Fatal("the failures were swallowed")
	}
	if res.ExpiredAssets != 1 || res.AccessLogRows != 3 {
		t.Errorf("a failed asset or a failed partition drop stopped the rest: %+v", res)
	}
}

func TestSweepListFailureIsReported(t *testing.T) {
	st := &fakeStore{listErr: errors.New("db down")}
	s := &Sweeper{Store: st, Requester: &fakeRequester{store: st}, AccessLogDays: 90, Log: slog.New(slog.DiscardHandler)}
	if _, err := s.Sweep(context.Background()); err == nil {
		t.Fatal("no error")
	}
}
