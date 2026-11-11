package signing

import (
	"context"
	"sync"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

// KeySetTTL is how long a KeySet serves a read before it reads the database again. A new key or a
// retirement therefore reaches the published set within a minute.
const KeySetTTL = 60 * time.Second

// KeyLister reads the published keys. *db.Repos implements it.
type KeyLister interface {
	ListSigningKeys(ctx context.Context, purpose string) ([]db.SigningKey, error)
}

func listPublic(ctx context.Context, l KeyLister) ([]PublicKey, error) {
	rows, err := l.ListSigningKeys(ctx, PurposeIntegrity)
	if err != nil {
		return nil, err
	}
	out := make([]PublicKey, len(rows))
	for i, r := range rows {
		out[i] = publicKeyFromRow(r)
	}
	return out, nil
}

// KeySet serves the public key set from a short-lived in-process cache. It reads only public data
// and needs no key service, so the edge role can use it without one. Keys are ordered by creation
// time, then key id. It is safe for concurrent use.
type KeySet struct {
	src KeyLister
	ttl time.Duration
	now func() time.Time

	mu     sync.Mutex
	keys   []PublicKey
	loaded time.Time
	valid  bool
}

// NewKeySet returns a KeySet over src. A ttl of zero or less, or above KeySetTTL, means KeySetTTL.
func NewKeySet(src KeyLister, ttl time.Duration, now func() time.Time) *KeySet {
	if ttl <= 0 || ttl > KeySetTTL {
		ttl = KeySetTTL
	}
	if now == nil {
		now = time.Now
	}
	return &KeySet{src: src, ttl: ttl, now: now}
}

// Get returns the published keys. A failed read is returned as the database error and nothing
// stale is served: the endpoint answers 503 until the database is back.
func (s *KeySet) Get(ctx context.Context) ([]PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.valid && s.now().Sub(s.loaded) < s.ttl {
		return clonePublic(s.keys), nil
	}
	keys, err := listPublic(ctx, s.src)
	if err != nil {
		s.valid = false
		return nil, err
	}
	s.keys, s.loaded, s.valid = keys, s.now(), true
	return clonePublic(keys), nil
}

func clonePublic(in []PublicKey) []PublicKey {
	out := make([]PublicKey, len(in))
	copy(out, in)
	return out
}
