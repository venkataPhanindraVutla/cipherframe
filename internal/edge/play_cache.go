package edge

import (
	"sync"
	"time"
)

// ttlCache is a small bounded cache with a time-to-live per entry, for the two lookups the
// playback routes make about a tenant (its settings, and the tenant of a session). It is not an
// LRU: when it is full it drops expired entries and, if that frees nothing, one arbitrary entry.
// The bound matters more than the policy: the keys include values a client chooses (a session ID
// in a path), so the cache must not grow with traffic.
//
// Only successful lookups are stored by callers; a failed lookup is retried on the next request.
type ttlCache[K comparable, V any] struct {
	mu  sync.Mutex
	m   map[K]ttlEntry[V]
	max int
	ttl time.Duration
	now func() time.Time
}

type ttlEntry[V any] struct {
	v       V
	expires time.Time
}

func newTTLCache[K comparable, V any](maxEntries int, ttl time.Duration, now func() time.Time) *ttlCache[K, V] {
	return &ttlCache[K, V]{m: make(map[K]ttlEntry[V], maxEntries), max: maxEntries, ttl: ttl, now: now}
}

func (c *ttlCache[K, V]) get(k K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok {
		var zero V
		return zero, false
	}
	if !c.now().Before(e.expires) {
		delete(c.m, k)
		var zero V
		return zero, false
	}
	return e.v, true
}

func (c *ttlCache[K, V]) put(k K, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if _, ok := c.m[k]; !ok && len(c.m) >= c.max {
		for key, e := range c.m {
			if !now.Before(e.expires) {
				delete(c.m, key)
			}
		}
		if len(c.m) >= c.max {
			for key := range c.m { // arbitrary: map iteration order is unspecified
				delete(c.m, key)
				break
			}
		}
	}
	c.m[k] = ttlEntry[V]{v: v, expires: now.Add(c.ttl)}
}
