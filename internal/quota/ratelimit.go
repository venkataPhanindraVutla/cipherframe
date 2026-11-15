package quota

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// bucket is a token bucket: it holds up to burst tokens and refills at rate tokens per second.
// Not safe for concurrent use; the Limiter guards it.
type bucket struct {
	rate, burst float64
	tokens      float64
	last        time.Time
}

// newBucket returns a full bucket that allows perMinute requests a minute, bursting up to
// perMinute at once.
func newBucket(perMinute int, now time.Time) *bucket {
	b := &bucket{last: now}
	b.set(perMinute)
	b.tokens = b.burst
	return b
}

// set changes the limit, keeping the tokens the bucket holds (capped at the new burst).
func (b *bucket) set(perMinute int) {
	b.rate, b.burst = float64(perMinute)/60, float64(perMinute)
	b.tokens = math.Min(b.tokens, b.burst)
}

// take removes one token. When there is none it returns how long until one is available.
func (b *bucket) take(now time.Time) (bool, time.Duration) {
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(b.burst, b.tokens+el*b.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration(math.Ceil((1 - b.tokens) / b.rate * float64(time.Second)))
}

const (
	limitsTTL  = 15 * time.Second // how long a key's limit is cached before it is read again
	bucketIdle = 10 * time.Minute // a bucket unused this long is dropped
	sweepEvery = time.Minute
	maxKeys    = 4096 // cache entries kept before the oldest are swept early
)

type keyState struct {
	b        *bucket // nil while the key is unlimited
	limit    int
	loadedAt time.Time
}

// Limiter is the per-API-key request rate limit of the control plane (ADR 0047). The state is in
// memory, so the limit is per process instance: running N instances allows a key up to N times its
// limit. Safe for concurrent use.
type Limiter struct {
	repos *db.Repos
	log   *slog.Logger
	now   func() time.Time

	mu        sync.Mutex
	keys      map[id.APIKeyID]*keyState
	lastSweep time.Time
}

// NewLimiter builds a Limiter that reads limits through repos. now defaults to time.Now.
func NewLimiter(repos *db.Repos, log *slog.Logger, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Limiter{repos: repos, log: log, now: now, keys: map[id.APIKeyID]*keyState{}}
}

// Allow takes one request from the key's bucket. The limit is the lower of the tenant's and the
// client's requests_per_minute, read from the database at most every 15 seconds per key. It
// returns false and the wait when the bucket is empty. A key with no limit is always allowed; so
// is any request when the limits cannot be read (the limiter fails open: it must not turn a
// database blip into an outage of the control plane).
func (l *Limiter) Allow(ctx context.Context, p auth.Principal) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	st := l.keys[p.KeyID]
	fresh := st != nil && now.Sub(st.loadedAt) < limitsTTL
	l.mu.Unlock()

	limit, loaded := -1, false
	if !fresh {
		var err error
		if limit, err = l.load(ctx, p); err != nil {
			l.log.WarnContext(ctx, "request limit unreadable; allowing the request")
			return true, 0
		}
		loaded = true
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if loaded {
		st = l.keys[p.KeyID]
		if st == nil {
			st = &keyState{}
			l.keys[p.KeyID] = st
		}
		st.loadedAt, st.limit = now, limit
		switch {
		case limit == 0:
			st.b = nil
		case st.b == nil:
			st.b = newBucket(limit, now)
		default:
			st.b.set(limit)
		}
	} else if st = l.keys[p.KeyID]; st == nil {
		return true, 0 // swept between the two critical sections: the next request reloads
	}
	l.sweep(now)
	if st.b == nil {
		return true, 0
	}
	return st.b.take(now)
}

// load returns the key's effective requests_per_minute, 0 for unlimited.
func (l *Limiter) load(ctx context.Context, p auth.Principal) (int, error) {
	t, c, err := limits(ctx, l.repos, p.TenantID, p.ClientID)
	if err != nil {
		return 0, err
	}
	if eff := Effective(t, c).RequestsPerMinute; eff != nil {
		return *eff, nil
	}
	return 0, nil
}

// sweep drops the state of keys that have not been seen for a while. Called with l.mu held.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < sweepEvery && len(l.keys) < maxKeys {
		return
	}
	l.lastSweep = now
	for k, st := range l.keys {
		if now.Sub(st.loadedAt) > bucketIdle {
			delete(l.keys, k)
		}
	}
}
