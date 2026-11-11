package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// LastUsedInterval is the minimum time between two last_used_at writes for one key.
const LastUsedInterval = time.Minute

// unauthenticatedDetail is the only detail ever returned for a failed authentication, whatever
// the reason (malformed, unknown prefix, wrong secret, expired previous secret, revoked, disabled).
const unauthenticatedDetail = "The API key is missing or invalid."

// Peppers is the versioned pepper set (ADR 0016). config.Peppers implements it.
type Peppers interface {
	// Get returns the pepper of a version.
	Get(version int) (config.Secret, bool)
	// Current returns the version used for new and rotated keys, and its pepper.
	Current() (int, config.Secret)
}

// Store is what verification reads and writes. *db.Repos implements it.
type Store interface {
	GetActiveAPIKeyByPrefix(ctx context.Context, prefix string) (db.AuthKey, error)
	TouchAPIKeyLastUsed(ctx context.Context, keyID id.APIKeyID, at time.Time) error
}

// Verifier authenticates presented API keys.
type Verifier struct {
	store   Store
	peppers Peppers
	now     func() time.Time
	log     *slog.Logger

	// dummy stands in for a stored hash when the prefix is unknown, so that unknown and known
	// prefixes cost the same HMAC and constant-time comparison.
	dummy []byte

	mu      sync.Mutex
	touched map[id.APIKeyID]time.Time
}

// NewVerifier returns a Verifier. now defaults to time.Now; tests inject a clock.
func NewVerifier(store Store, peppers Peppers, log *slog.Logger, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	dummy := make([]byte, 32)
	_, _ = rand.Read(dummy) // a failed read leaves zeros, which is still a value no HMAC equals
	return &Verifier{store: store, peppers: peppers, now: now, log: log, dummy: dummy, touched: map[id.APIKeyID]time.Time{}}
}

func unauthenticated() error { return errs.New(errs.Unauthenticated, unauthenticatedDetail) }

// Authenticate checks the value of the Authorization header's bearer token (the part after the
// scheme). Every rejection is the same unauthenticated error. A stored key whose pepper version is
// not configured is a server fault (internal_error, logged without values). A store failure is
// returned as the store's own error (for example dependency_unavailable): authentication fails
// closed.
func (v *Verifier) Authenticate(ctx context.Context, token string) (Principal, error) {
	key, err := ParseKey(token)
	if err != nil {
		return Principal{}, unauthenticated()
	}
	stored, err := v.store.GetActiveAPIKeyByPrefix(ctx, key.Prefix())
	if err != nil {
		var e *errs.Error
		if errors.As(err, &e) && e.Code == errs.NotFound {
			v.spendDummyWork(key)
			return Principal{}, unauthenticated()
		}
		if errors.As(err, &e) {
			return Principal{}, err
		}
		return Principal{}, errs.Wrap(errs.InternalError, "authentication lookup failed", err)
	}

	now := v.now()
	ok, err := v.matches(key, stored, now)
	if err != nil {
		return Principal{}, err
	}
	if !ok || stored.RevokedAt != nil || stored.ClientDisabledAt != nil || stored.TenantDisabledAt != nil {
		return Principal{}, unauthenticated()
	}

	v.touchLastUsed(ctx, stored, now)
	return Principal{
		TenantID: stored.TenantID,
		ClientID: stored.ClientID,
		KeyID:    stored.ID,
		Scopes:   append([]db.Scope(nil), stored.Scopes...),
	}, nil
}

// matches compares the presented secret with the current hash and, inside the overlap window,
// with the previous one.
func (v *Verifier) matches(key Key, stored db.AuthKey, now time.Time) (bool, error) {
	pepper, found := v.peppers.Get(stored.PepperVersion)
	if !found {
		v.log.Error("api key references an unconfigured pepper version",
			slog.String("key_id", stored.ID.String()), slog.Int("pepper_version", stored.PepperVersion))
		return false, errs.New(errs.InternalError, "An internal error occurred.")
	}
	if hmac.Equal(key.Hash([]byte(pepper.Reveal())), stored.SecretHash) {
		return true, nil
	}
	prev := stored.Previous
	if prev == nil || !prev.ValidUntil.After(now) {
		return false, nil
	}
	prevPepper, found := v.peppers.Get(prev.PepperVersion)
	if !found {
		v.log.Error("api key references an unconfigured pepper version",
			slog.String("key_id", stored.ID.String()), slog.Int("pepper_version", prev.PepperVersion))
		return false, errs.New(errs.InternalError, "An internal error occurred.")
	}
	return hmac.Equal(key.Hash([]byte(prevPepper.Reveal())), prev.Hash), nil
}

// spendDummyWork performs the HMAC and the comparison an existing key would cost, so response
// time does not reveal which prefixes exist.
func (v *Verifier) spendDummyWork(key Key) {
	_, pepper := v.peppers.Current()
	_ = hmac.Equal(key.Hash([]byte(pepper.Reveal())), v.dummy)
}

// touchLastUsed records the use at most once per LastUsedInterval per key. It looks at the
// stored last_used_at (shared across processes) and at an in-memory mark (so a burst of requests
// right after a use does not all write). A failed write is logged and ignored: it must not
// fail an authenticated request.
func (v *Verifier) touchLastUsed(ctx context.Context, k db.AuthKey, now time.Time) {
	if k.LastUsedAt != nil && now.Sub(*k.LastUsedAt) < LastUsedInterval {
		return
	}
	v.mu.Lock()
	if last, ok := v.touched[k.ID]; ok && now.Sub(last) < LastUsedInterval {
		v.mu.Unlock()
		return
	}
	v.touched[k.ID] = now
	if len(v.touched) > 4096 { // bound the map: drop marks that no longer throttle anything
		for kid, t := range v.touched {
			if now.Sub(t) >= LastUsedInterval {
				delete(v.touched, kid)
			}
		}
	}
	v.mu.Unlock()

	if err := v.store.TouchAPIKeyLastUsed(ctx, k.ID, now); err != nil {
		var e *errs.Error
		code := "unknown"
		if errors.As(err, &e) {
			code = string(e.Code)
		}
		v.log.Warn("could not record api key use", slog.String("key_id", k.ID.String()), slog.String("code", code))
	}
}

// BearerToken extracts the token from an Authorization header value: the scheme "Bearer"
// (case-insensitive), exactly one space, then a token without whitespace.
func BearerToken(header string) (string, bool) {
	const scheme = "bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	tok := header[len(scheme):]
	if strings.ContainsAny(tok, " \t\r\n") {
		return "", false
	}
	return tok, true
}
