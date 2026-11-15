package quota

import (
	"math"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

func TestExceeds(t *testing.T) {
	cases := []struct {
		used, add, limit int64
		want             bool
	}{
		{0, 1, 1, false},                            // reaching the limit exactly is allowed
		{1, 1, 1, true},                             // one over
		{999, 1, 1000, false},                       // just under
		{1000, 1, 1000, true},                       // at the limit, one more is over
		{400, 600, 1000, false},                     // fills it exactly
		{400, 601, 1000, true},                      // one byte over
		{0, 2000, 1000, true},                       // a single request larger than the limit
		{1001, 0, 1000, true},                       // already over (a limit lowered below usage) and nothing added
		{math.MaxInt64 - 1, 5, math.MaxInt64, true}, // no overflow
		{5, math.MaxInt64, math.MaxInt64, true},
		{0, math.MaxInt64, math.MaxInt64, false},
	}
	for _, c := range cases {
		if got := Exceeds(c.used, c.add, c.limit); got != c.want {
			t.Errorf("Exceeds(%d, %d, %d) = %v, want %v", c.used, c.add, c.limit, got, c.want)
		}
	}
}

func TestEffectiveTakesTheLowerLimit(t *testing.T) {
	i64 := func(n int64) *int64 { return &n }
	n := func(n int) *int { return &n }
	tenant := db.Quotas{StorageBytes: i64(1000), ConcurrentSessions: n(10)}
	client := db.Quotas{StorageBytes: i64(400), TranscodeMinutesPerMonth: n(60), RequestsPerMinute: n(5)}
	got := Effective(tenant, client)
	if *got.StorageBytes != 400 || *got.ConcurrentSessions != 10 || *got.TranscodeMinutesPerMonth != 60 || *got.RequestsPerMinute != 5 {
		t.Fatalf("effective = %+v", got)
	}
	// A client override above the tenant's limit cannot raise it.
	got = Effective(db.Quotas{StorageBytes: i64(100)}, db.Quotas{StorageBytes: i64(900)})
	if *got.StorageBytes != 100 {
		t.Fatalf("storage = %d", *got.StorageBytes)
	}
	if e := Effective(db.Quotas{}, db.Quotas{}); e.StorageBytes != nil || e.ConcurrentSessions != nil || e.RequestsPerMinute != nil || e.TranscodeMinutesPerMonth != nil {
		t.Fatalf("no limits must stay unlimited: %+v", e)
	}
}

func TestMonthBoundsAreUTC(t *testing.T) {
	zone := time.FixedZone("late", -10*3600)
	// 23:30 on 31 January in UTC-10 is already 1 February in UTC.
	from, until := MonthBounds(time.Date(2026, 1, 31, 23, 30, 0, 0, zone))
	if !from.Equal(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)) || !until.Equal(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("bounds = %v .. %v", from, until)
	}
	from, until = MonthBounds(time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC))
	if !from.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) || !until.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("december bounds = %v .. %v", from, until)
	}
}

func TestAboveTenant(t *testing.T) {
	i64 := func(n int64) *int64 { return &n }
	n := func(n int) *int { return &n }
	tenant := db.Quotas{StorageBytes: i64(100), ConcurrentSessions: n(5)}
	if f := aboveTenant(db.Quotas{StorageBytes: i64(100), ConcurrentSessions: n(5), RequestsPerMinute: n(1000)}, tenant); len(f) != 0 {
		t.Fatalf("equal or unlimited tenant limits are fine: %v", f)
	}
	f := aboveTenant(db.Quotas{StorageBytes: i64(101), ConcurrentSessions: n(6)}, tenant)
	if len(f) != 2 || f[0].Field != LimitStorageBytes || f[1].Field != LimitConcurrentSessions {
		t.Fatalf("fields = %v", f)
	}
}

func TestBucketBurstThenRefill(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := newBucket(60, now) // 1 token a second, burst of 60
	for i := range 60 {
		if ok, _ := b.take(now); !ok {
			t.Fatalf("request %d refused inside the burst", i+1)
		}
	}
	ok, wait := b.take(now)
	if ok || wait != time.Second {
		t.Fatalf("61st request: ok=%v wait=%v, want refused with 1s", ok, wait)
	}
	// Half a second later there is still no whole token; the wait shrinks.
	ok, wait = b.take(now.Add(500 * time.Millisecond))
	if ok || wait != 500*time.Millisecond {
		t.Fatalf("after 500ms: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := b.take(now.Add(time.Second)); !ok {
		t.Fatal("a token should be back after a second")
	}
	if ok, _ := b.take(now.Add(time.Second)); ok {
		t.Fatal("only one token came back")
	}
	// A long pause refills to the burst and no further.
	later := now.Add(time.Hour)
	for i := range 60 {
		if ok, _ := b.take(later); !ok {
			t.Fatalf("request %d after the pause refused", i+1)
		}
	}
	if ok, _ := b.take(later); ok {
		t.Fatal("the bucket refilled past its burst")
	}
}

func TestBucketLimitChange(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := newBucket(600, now)
	b.set(2) // lowering the limit cuts the stored tokens to the new burst
	for range 2 {
		if ok, _ := b.take(now); !ok {
			t.Fatal("refused inside the new burst")
		}
	}
	if ok, wait := b.take(now); ok || wait != 30*time.Second {
		t.Fatalf("ok=%v wait=%v, want refused with 30s", ok, wait)
	}
}
