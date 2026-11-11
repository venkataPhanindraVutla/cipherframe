package signing

import (
	"crypto/ed25519"
	"sync"
	"time"
)

// DefaultSeedTTL is how long an unwrapped key stays in memory.
const DefaultSeedTTL = 5 * time.Minute

type cachedKey struct {
	priv    ed25519.PrivateKey
	expires time.Time
}

// seedCache holds unwrapped private keys for a bounded time. An entry is zeroed when it expires,
// when it is evicted, and when the cache is closed. Signing happens while the lock is held, so an
// eviction can never clear a key that a signature is still reading.
type seedCache struct {
	mu  sync.Mutex
	m   map[string]*cachedKey
	ttl time.Duration
	now func() time.Time
}

func newSeedCache(ttl time.Duration, now func() time.Time) *seedCache {
	return &seedCache{m: map[string]*cachedKey{}, ttl: ttl, now: now}
}

// evictExpired zeroes and removes every expired entry. The caller holds mu.
func (c *seedCache) evictExpired() {
	now := c.now()
	for id, e := range c.m {
		if !now.Before(e.expires) {
			clear(e.priv)
			delete(c.m, id)
		}
	}
}

// sign signs msg with the cached key, reporting false on a miss.
func (c *seedCache) sign(keyID string, msg []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictExpired()
	e, ok := c.m[keyID]
	if !ok {
		return nil, false
	}
	return ed25519.Sign(e.priv, msg), true
}

// put stores priv, which the cache now owns and zeroes on eviction. A key already cached under
// keyID is zeroed and replaced.
func (c *seedCache) put(keyID string, priv ed25519.PrivateKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictExpired()
	if old, ok := c.m[keyID]; ok {
		clear(old.priv)
	}
	c.m[keyID] = &cachedKey{priv: priv, expires: c.now().Add(c.ttl)}
}

// evict zeroes and removes one key.
func (c *seedCache) evict(keyID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[keyID]; ok {
		clear(e.priv)
		delete(c.m, keyID)
	}
}

// close zeroes and removes every key.
func (c *seedCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, e := range c.m {
		clear(e.priv)
		delete(c.m, id)
	}
}
