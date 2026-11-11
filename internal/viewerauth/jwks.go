package viewerauth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
)

// JWKS fetching and caching (ADR 0029).
const (
	// JWKSTTL is how long a fetched document is used.
	JWKSTTL = 10 * time.Minute
	// JWKSMinRefetch is the shortest time between two fetch attempts for one tenant, whether the
	// last one succeeded or not. A token that names an unknown kid can trigger a refetch, so
	// without it anyone could make Cipherframe hammer a tenant's JWKS server.
	JWKSMinRefetch = 30 * time.Second
	// MaxJWKSBytes is the largest JWKS document read.
	MaxJWKSBytes = 64 << 10
	// jwksCacheMax bounds the number of tenants cached.
	jwksCacheMax = 1024
)

// jwksCache holds one parsed JWKS document per tenant.
type jwksCache struct {
	client *outbound.Client
	now    func() time.Time

	mu sync.Mutex
	m  map[string]*jwksEntry
}

// jwksEntry is one tenant's document. Its mutex is held while a fetch is in flight, so concurrent
// requests of one tenant share one fetch instead of each making their own.
type jwksEntry struct {
	mu        sync.Mutex
	url       string
	keys      map[string]PublicKey
	fetchedAt time.Time
	tried     time.Time // the last fetch attempt, successful or not
}

func newJWKSCache(c *outbound.Client, now func() time.Time) *jwksCache {
	return &jwksCache{client: c, now: now, m: map[string]*jwksEntry{}}
}

func (c *jwksCache) entry(tenant, url string) *jwksEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[tenant]
	if e == nil || e.url != url { // a changed URL starts from nothing
		if e == nil && len(c.m) >= jwksCacheMax {
			for k := range c.m { // arbitrary: the bound matters more than the policy
				delete(c.m, k)
				break
			}
		}
		e = &jwksEntry{url: url}
		c.m[tenant] = e
	}
	return e
}

// lookup finds the key with the given kid in the tenant's JWKS, fetching the document when it is
// missing or older than JWKSTTL, and refetching (at most once per JWKSMinRefetch) when the kid is
// not in it. A fetch failure is a miss: it is never an error that reveals why.
func (c *jwksCache) lookup(ctx context.Context, tenant, url, kid string) (PublicKey, bool) {
	e := c.entry(tenant, url)
	e.mu.Lock()
	defer e.mu.Unlock()
	now := c.now()

	fresh := e.keys != nil && now.Sub(e.fetchedAt) < JWKSTTL
	if fresh {
		if k, ok := e.keys[kid]; ok {
			return k, true
		}
	} else {
		e.keys = nil // stale: never used, even when the refresh below fails
	}
	if !e.tried.IsZero() && now.Sub(e.tried) < JWKSMinRefetch {
		return PublicKey{}, false
	}
	e.tried = now
	keys, err := c.fetch(ctx, url)
	if err != nil {
		return PublicKey{}, false
	}
	e.keys, e.fetchedAt = keys, now
	k, ok := keys[kid]
	return k, ok
}

// errFetch is the only error a fetch reports: the cause is not needed and must not leak.
var errFetch = errors.New("viewerauth: the JWKS could not be fetched")

func (c *jwksCache) fetch(ctx context.Context, url string) (map[string]PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errFetch
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cipherframe-edge")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, errFetch
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, errFetch
	}
	body, err := outbound.ReadAll(res.Body, MaxJWKSBytes)
	if err != nil {
		return nil, errFetch
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		return nil, errFetch
	}
	return keys, nil
}
