package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

// Purposes, algorithms and states.
const (
	PurposeIntegrity = "integrity"
	AlgEd25519       = "ed25519"
	StateActive      = "active"
	StateRetired     = "retired"
)

// Audit actions written when the key set changes (audit_events.action).
const (
	AuditRotate = "signing_key.rotate"
	AuditRetire = "signing_key.retire"
)

// wrapAttempts bounds how often a seed is wrapped when the provider answers under a different KEK
// version than Current reported (a rotation between the two calls).
const wrapAttempts = 2

// PublicKey is the public half of a signing key and its place in the life cycle. It holds no
// secret.
type PublicKey struct {
	KeyID       string
	Algorithm   string
	PublicKey   ed25519.PublicKey
	Status      string // StateActive or StateRetired
	Current     bool   // the one key that signs
	CreatedAt   time.Time
	ActivatedAt time.Time
	RetiredAt   *time.Time
}

// PublicKeyBase64 returns the key in standard base64, as the key set publishes it.
func (k PublicKey) PublicKeyBase64() string { return base64.StdEncoding.EncodeToString(k.PublicKey) }

func publicKeyFromRow(r db.SigningKey) PublicKey {
	return PublicKey{
		KeyID: r.KeyID, Algorithm: r.Algorithm, PublicKey: ed25519.PublicKey(append([]byte(nil), r.PublicKey...)),
		Status: r.State, Current: r.IsCurrent, CreatedAt: r.CreatedAt, ActivatedAt: r.ActivatedAt, RetiredAt: r.RetiredAt,
	}
}

// Signer signs with the current integrity key. It is what the worker uses (M5-1); the signature is
// a raw Ed25519 signature, and DSSE wrapping happens in the caller.
type Signer interface {
	// Sign returns the id of the current key and its signature over message.
	Sign(ctx context.Context, message []byte) (keyID string, sig []byte, err error)
	// PublicKeys returns every active and retired key, oldest first.
	PublicKeys(ctx context.Context) ([]PublicKey, error)
}

// Audit says whom to record an audit event for. A zero TenantID records none (the startup path
// has no caller).
type Audit struct {
	TenantID id.TenantID
	Actor    auth.Actor
}

// Manager creates, rotates and retires signing keys and signs with the current one. It is safe for
// concurrent use.
type Manager struct {
	repos *db.Repos
	begin db.Beginner
	reg   *kms.Registry
	log   *slog.Logger
	now   func() time.Time
	cache *seedCache
}

var _ Signer = (*Manager)(nil)

// Option configures a Manager.
type Option func(*options)

type options struct {
	now func() time.Time
	ttl time.Duration
}

// WithClock sets the clock (tests).
func WithClock(now func() time.Time) Option { return func(o *options) { o.now = now } }

// WithSeedTTL sets how long an unwrapped key stays cached. Values above DefaultSeedTTL are
// reduced to it: a key is never kept longer than five minutes.
func WithSeedTTL(d time.Duration) Option { return func(o *options) { o.ttl = d } }

// NewManager returns a Manager over pool, which is a *pgxpool.Pool. reg wraps new seeds with its
// current provider and unwraps with the provider that made each one. log may be nil.
func NewManager(pool dbgen.DBTX, reg *kms.Registry, log *slog.Logger, opts ...Option) *Manager {
	if log == nil {
		log = slog.Default()
	}
	o := options{now: time.Now, ttl: DefaultSeedTTL}
	for _, f := range opts {
		f(&o)
	}
	if o.ttl <= 0 || o.ttl > DefaultSeedTTL {
		o.ttl = DefaultSeedTTL
	}
	b, _ := pool.(db.Beginner)
	return &Manager{repos: db.New(pool), begin: b, reg: reg, log: log, now: o.now, cache: newSeedCache(o.ttl, o.now)}
}

// Close zeroes every cached key. The Manager may still be used; keys are unwrapped again.
func (m *Manager) Close() { m.cache.close() }

func (m *Manager) tx(ctx context.Context, fn func(*db.Repos) error) error {
	if m.begin == nil {
		return errs.New(errs.InternalError, "internal error")
	}
	return db.Tx(ctx, m.begin, fn)
}

// newKey generates a key pair and its wrapped seed. It touches only the key service, never the
// database, so a key-service failure leaves nothing behind.
func (m *Manager) newKey(ctx context.Context) (db.NewSigningKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, err := rand.Read(seed); err != nil {
		return db.NewSigningKey{}, errs.Wrap(errs.InternalError, "internal error", errors.New("signing: no randomness available"))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	defer clear(priv)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return db.NewSigningKey{}, errs.New(errs.InternalError, "internal error")
	}
	keyID := id.New[id.SigningKeyKind]().String()
	envelope, err := m.seal(ctx, keyID, seed)
	if err != nil {
		return db.NewSigningKey{}, err
	}
	return db.NewSigningKey{
		KeyID: keyID, Purpose: PurposeIntegrity, Algorithm: AlgEd25519,
		PublicKey: append([]byte(nil), pub...), PrivateEnvelope: envelope, At: m.now().UTC(),
	}, nil
}

// seal wraps seed for keyID under the current KEK. The associated data names the KEK version, so
// it is computed from Current and the result is checked against it: a wrap that came back under
// another version is retried once, then refused.
func (m *Manager) seal(ctx context.Context, keyID string, seed []byte) ([]byte, error) {
	p := m.reg.Current()
	for range wrapAttempts {
		ref, err := p.Current(ctx)
		if err != nil {
			return nil, kms.ToAppError(err)
		}
		w, err := p.Wrap(ctx, seed, aad(binding{
			keyID: keyID, algorithm: AlgEd25519, provider: p.Name(), kekKeyID: ref.KeyID, kekVersion: ref.Version,
		}))
		if err != nil {
			return nil, kms.ToAppError(err)
		}
		if w.Provider == p.Name() && w.Ref() == ref && len(w.Ciphertext) > 0 {
			return encodeEnvelope(w), nil
		}
	}
	return nil, kms.ToAppError(kms.New(kms.Other, p.Name(), "wrap", "provider wrapped under an unexpected KEK version"))
}

// open unwraps the key's envelope and returns its private key. The caller owns the result and
// clears it. A seed that does not match the published public key is refused.
func (m *Manager) open(ctx context.Context, row db.SigningKey) (ed25519.PrivateKey, error) {
	w, err := decodeEnvelope(row.PrivateEnvelope)
	if err != nil {
		m.logOpenFailure(ctx, row, err)
		return nil, errs.Wrap(errs.InternalError, "internal error", err)
	}
	seed, err := m.reg.Unwrap(ctx, w, aad(binding{
		keyID: row.KeyID, algorithm: row.Algorithm, provider: w.Provider, kekKeyID: w.KeyID, kekVersion: w.Version,
	}))
	if err != nil {
		m.logOpenFailure(ctx, row, err)
		return nil, kms.ToAppError(err)
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		m.logOpenFailure(ctx, row, ErrEnvelope)
		return nil, errs.Wrap(errs.InternalError, "internal error", ErrEnvelope)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if subtle.ConstantTimeCompare(priv[ed25519.SeedSize:], row.PublicKey) != 1 {
		clear(priv)
		m.logOpenFailure(ctx, row, ErrEnvelope)
		return nil, errs.Wrap(errs.InternalError, "internal error", ErrEnvelope)
	}
	return priv, nil
}

// logOpenFailure records identifiers, never values.
func (m *Manager) logOpenFailure(ctx context.Context, row db.SigningKey, err error) {
	attrs := []any{slog.String("signing_key_id", row.KeyID), slog.String("kind", kms.KindOf(err).String())}
	switch {
	case kms.IsIntegrityFailure(err), errors.Is(err, ErrEnvelope):
		m.log.ErrorContext(ctx, "signing key failed authentication (integrity failure)", attrs...)
	case kms.KindOf(err) == kms.NotConfigured, kms.KindOf(err) == kms.Denied:
		m.log.ErrorContext(ctx, "signing key provider is not usable", attrs...)
	}
}

func (m *Manager) audit(ctx context.Context, tx *db.Repos, a Audit, action, target string) error {
	if a.TenantID.IsZero() {
		return nil
	}
	_, err := tx.InsertAuditEvent(ctx, db.NewAuditEvent{
		TenantID: a.TenantID, ClientID: a.Actor.ClientID, APIKeyID: a.Actor.KeyID,
		Action: action, Target: target, RequestID: a.Actor.RequestID,
	})
	return err
}

func isNotFound(err error) bool {
	var e *errs.Error
	return errors.As(err, &e) && e.Code == errs.NotFound
}

// EnsureCurrent creates the first integrity key when the deployment has none, and does nothing
// otherwise. It is safe to call from every process at startup: an advisory lock makes concurrent
// callers produce one key. A key-service failure is returned as dependency_unavailable and creates
// nothing.
func (m *Manager) EnsureCurrent(ctx context.Context) error {
	if _, err := m.repos.GetCurrentSigningKey(ctx, PurposeIntegrity); err == nil {
		return nil
	} else if !isNotFound(err) {
		return err
	}
	// Wrap before taking the lock: a caller that loses the race discards its key, and a provider
	// call never holds a database transaction open.
	nk, err := m.newKey(ctx)
	if err != nil {
		return err
	}
	created := false
	if err := m.tx(ctx, func(tx *db.Repos) error {
		if err := tx.LockSigningKeys(ctx); err != nil {
			return err
		}
		switch _, err := tx.GetCurrentSigningKey(ctx, PurposeIntegrity); {
		case err == nil:
			return nil
		case !isNotFound(err):
			return err
		}
		if _, err := tx.InsertSigningKey(ctx, nk); err != nil {
			return err
		}
		created = true
		return nil
	}); err != nil {
		return err
	}
	if created {
		m.log.InfoContext(ctx, "created the first integrity signing key", slog.String("signing_key_id", nk.KeyID))
	}
	return nil
}

// Rotate creates a new current key. The previous current key stays active: it is still published
// and still verifies, and only stops signing. It records an audit event for a.
func (m *Manager) Rotate(ctx context.Context, a Audit) (PublicKey, error) {
	nk, err := m.newKey(ctx)
	if err != nil {
		return PublicKey{}, err
	}
	var row db.SigningKey
	if err := m.tx(ctx, func(tx *db.Repos) error {
		if err := tx.LockSigningKeys(ctx); err != nil {
			return err
		}
		var err error
		if row, err = tx.InsertSigningKey(ctx, nk); err != nil {
			return err
		}
		return m.audit(ctx, tx, a, AuditRotate, row.KeyID)
	}); err != nil {
		return PublicKey{}, err
	}
	m.log.InfoContext(ctx, "rotated the integrity signing key", slog.String("signing_key_id", row.KeyID))
	return publicKeyFromRow(row), nil
}

// Retire marks a key retired. The current key cannot be retired (conflict): rotate first. A retired
// key stays published with status retired, so records it signed still verify, and never signs
// again. Retiring a retired key changes nothing. It records an audit event for a when it retires.
func (m *Manager) Retire(ctx context.Context, keyID string, a Audit) (PublicKey, error) {
	if _, err := id.Parse[id.SigningKeyKind](keyID); err != nil {
		return PublicKey{}, errs.New(errs.NotFound, "No such signing key.")
	}
	var row db.SigningKey
	if err := m.tx(ctx, func(tx *db.Repos) error {
		if err := tx.LockSigningKeys(ctx); err != nil {
			return err
		}
		cur, err := tx.GetSigningKey(ctx, keyID)
		if err != nil {
			if isNotFound(err) {
				return errs.New(errs.NotFound, "No such signing key.")
			}
			return err
		}
		switch {
		case cur.State == StateRetired:
			row = cur
			return nil
		case cur.IsCurrent:
			return errs.New(errs.Conflict, "The current signing key cannot be retired. Rotate first.")
		}
		if row, err = tx.RetireSigningKey(ctx, keyID, m.now().UTC()); err != nil {
			return err
		}
		return m.audit(ctx, tx, a, AuditRetire, keyID)
	}); err != nil {
		return PublicKey{}, err
	}
	m.cache.evict(keyID)
	row.PrivateEnvelope = nil
	return publicKeyFromRow(row), nil
}

// PublicKeys returns every key, active and retired, oldest first, read fresh from the database.
func (m *Manager) PublicKeys(ctx context.Context) ([]PublicKey, error) {
	return listPublic(ctx, m.repos)
}

// Sign signs message with the current key. The unwrapped key is cached for at most five minutes.
// A key-service failure is dependency_unavailable; no failure yields a signature.
func (m *Manager) Sign(ctx context.Context, message []byte) (string, []byte, error) {
	row, err := m.repos.GetCurrentSigningKey(ctx, PurposeIntegrity)
	if err != nil {
		if isNotFound(err) {
			return "", nil, errs.Wrap(errs.InternalError, "internal error", errors.New("signing: no current signing key"))
		}
		return "", nil, err
	}
	if sig, ok := m.cache.sign(row.KeyID, message); ok {
		return row.KeyID, sig, nil
	}
	priv, err := m.open(ctx, row)
	if err != nil {
		return "", nil, err
	}
	m.cache.put(row.KeyID, priv) // the cache now owns priv
	sig, ok := m.cache.sign(row.KeyID, message)
	if !ok { // evicted between put and sign: only possible with a zero TTL
		return "", nil, errs.New(errs.InternalError, "internal error")
	}
	return row.KeyID, sig, nil
}
