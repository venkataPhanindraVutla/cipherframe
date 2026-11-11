package contentkey

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

// wrapAttempts bounds how often Create retries when the provider wraps under a different KEK
// version than Current reported (a rotation between the two calls).
const wrapAttempts = 2

// Manager creates, reads and destroys content keys. Every method is scoped to a tenant. It is safe
// for concurrent use.
type Manager struct {
	repos *db.Repos
	reg   *kms.Registry
	log   *slog.Logger
}

// NewManager returns a Manager that reads through pool and wraps with reg's current provider.
// pool is a *pgxpool.Pool. Create and Destroy use the caller's transaction instead. log may be nil.
func NewManager(pool dbgen.DBTX, reg *kms.Registry, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{repos: db.New(pool), reg: reg, log: log}
}

// Create generates a content key, wraps it with the current provider and inserts it in the
// caller's transaction tx, for an asset of tenant. A second Create for the same asset returns
// conflict and never a second key (invariant I7); an asset of another tenant returns not_found.
//
// The returned ContentKey holds the plaintext key; the caller should Zero it when finished.
// Provider failures are mapped like kms.ToAppError, and no failure yields a key.
func (m *Manager) Create(ctx context.Context, tx *db.Repos, tenant id.TenantID, asset id.AssetID) (ContentKey, error) {
	if tx == nil || tenant.IsZero() || asset.IsZero() {
		return ContentKey{}, errs.New(errs.InvalidRequest, "a transaction, tenant and asset are required")
	}
	// Report an existing key before spending a provider call. The unique constraint remains the
	// authority when two requests race.
	switch _, err := tx.GetContentKey(ctx, tenant, asset); {
	case err == nil:
		return ContentKey{}, errs.New(errs.Conflict, "the asset already has a content key")
	case !isNotFound(err):
		return ContentKey{}, err
	}

	key := make([]byte, KeyBytes)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return ContentKey{}, errs.Wrap(errs.InternalError, "internal error", errors.New("contentkey: no randomness available"))
	}

	keyID := id.New[id.ContentKeyKind]()
	wrapped, err := m.wrap(ctx, key, asset, keyID)
	if err != nil {
		return ContentKey{}, err
	}
	if _, err := tx.CreateContentKey(ctx, tenant, db.NewContentKeyRow{
		ID:              keyID,
		AssetID:         asset,
		KEK:             db.KEKRef{Provider: wrapped.Provider, KeyID: wrapped.KeyID, Version: wrapped.Version},
		EnvelopeVersion: EnvelopeVersion,
		Wrapped:         wrapped.Ciphertext,
	}); err != nil {
		return ContentKey{}, err
	}
	return newContentKey(keyID, asset, key), nil
}

// wrap wraps key for the slot (asset, keyID) under the current provider's current KEK. The
// associated data names the KEK version, so it is computed from Current and the result is checked
// against it: a wrap that came back under another version is retried once, then refused.
func (m *Manager) wrap(ctx context.Context, key []byte, asset id.AssetID, keyID id.ContentKeyID) (kms.Wrapped, error) {
	p := m.reg.Current()
	for range wrapAttempts {
		ref, err := p.Current(ctx)
		if err != nil {
			return kms.Wrapped{}, kms.ToAppError(err)
		}
		aad := AAD(Binding{
			EnvelopeVersion: EnvelopeVersion, AssetID: asset, ContentKeyID: keyID,
			Provider: p.Name(), KEKKeyID: ref.KeyID, KEKVersion: ref.Version,
		})
		if aad == nil {
			return kms.Wrapped{}, errs.Wrap(errs.InternalError, "internal error", kms.ErrOther)
		}
		w, err := p.Wrap(ctx, key, aad)
		if err != nil {
			return kms.Wrapped{}, kms.ToAppError(err)
		}
		if w.Provider == p.Name() && w.Ref() == ref && len(w.Ciphertext) > 0 {
			return w, nil
		}
	}
	// The provider keeps answering for a KEK other than the one it reported. Fail closed.
	return kms.Wrapped{}, kms.ToAppError(kms.New(kms.Other, p.Name(), "wrap", "provider wrapped under an unexpected KEK version"))
}

// Get reads the asset's content key and unwraps it with the provider that wrapped it. It returns
// not_found when the asset has no key (including after Destroy), and a mapped provider error
// otherwise. A key that fails authentication is logged as an integrity failure, with identifiers
// only, and is reported as internal_error. No failure yields a key.
func (m *Manager) Get(ctx context.Context, tenant id.TenantID, asset id.AssetID) (ContentKey, error) {
	row, err := m.repos.GetContentKey(ctx, tenant, asset)
	if err != nil {
		return ContentKey{}, err
	}
	if row.EnvelopeVersion != EnvelopeVersion {
		m.log.ErrorContext(ctx, "content key has an unsupported envelope version",
			slog.String("asset_id", asset.String()), slog.Int("envelope_version", row.EnvelopeVersion))
		return ContentKey{}, kms.ToAppError(kms.New(kms.Other, row.KEK.Provider, "unwrap", "unsupported envelope version"))
	}
	aad := AAD(Binding{
		EnvelopeVersion: row.EnvelopeVersion, AssetID: row.AssetID, ContentKeyID: row.ID,
		Provider: row.KEK.Provider, KEKKeyID: row.KEK.KeyID, KEKVersion: row.KEK.Version,
	})
	plain, err := m.reg.Unwrap(ctx, kms.Wrapped{
		Provider: row.KEK.Provider, KeyID: row.KEK.KeyID, Version: row.KEK.Version, Ciphertext: row.Wrapped,
	}, aad)
	if err != nil {
		m.logUnwrapFailure(ctx, row, err)
		return ContentKey{}, kms.ToAppError(err)
	}
	defer clear(plain)
	if len(plain) != KeyBytes {
		// A provider returned something that is not a content key. Never pass it on.
		m.logUnwrapFailure(ctx, row, kms.New(kms.Invalid, row.KEK.Provider, "unwrap", "unwrapped key has the wrong length"))
		return ContentKey{}, kms.ToAppError(kms.New(kms.Invalid, row.KEK.Provider, "unwrap", "unwrapped key has the wrong length"))
	}
	return newContentKey(row.ID, row.AssetID, plain), nil
}

// Destroy deletes the asset's content key row in the caller's transaction and reports whether a
// row was deleted. Crypto-shredding (M6) calls it: the row is destroyed, not flagged, so every
// copy of the ciphertext is unreadable afterwards. Another tenant's asset deletes nothing.
func (m *Manager) Destroy(ctx context.Context, tx *db.Repos, tenant id.TenantID, asset id.AssetID) (bool, error) {
	if tx == nil {
		return false, errs.New(errs.InvalidRequest, "a transaction is required")
	}
	n, err := tx.DeleteContentKey(ctx, tenant, asset)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// logUnwrapFailure records identifiers, never values. A failed authentication is an integrity
// failure; an unconfigured provider is an operator problem. Outages are left to the caller, which
// sees the retryable error.
func (m *Manager) logUnwrapFailure(ctx context.Context, row db.ContentKeyRow, err error) {
	attrs := []any{
		slog.String("asset_id", row.AssetID.String()),
		slog.String("content_key_id", row.ID.String()),
		slog.String("provider", row.KEK.Provider),
		slog.String("kek_key_id", row.KEK.KeyID),
		slog.String("kek_version", row.KEK.Version),
		slog.String("kind", kms.KindOf(err).String()),
	}
	switch {
	case kms.IsIntegrityFailure(err):
		m.log.ErrorContext(ctx, "content key failed authentication (integrity failure)", attrs...)
	case kms.KindOf(err) == kms.NotConfigured, kms.KindOf(err) == kms.Denied:
		m.log.ErrorContext(ctx, "content key provider is not usable", attrs...)
	}
}

func isNotFound(err error) bool {
	var e *errs.Error
	return errors.As(err, &e) && e.Code == errs.NotFound
}
