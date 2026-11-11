package db

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// MaxPlaybackJWTKeys is the most public JWKs a tenant may keep (ADR 0029).
const MaxPlaybackJWTKeys = 20

// DefaultViewerClaim is the JWT claim the viewer ID is read from unless the tenant configures
// another.
const DefaultViewerClaim = "sub"

// PlaybackAuth is a tenant's configuration for authorising browser-started playback sessions with
// a JWT or a signed callback (ADR 0029, 0031). A tenant without a stored row has both methods off
// (DefaultPlaybackAuth); UpdatedAt is then the zero time.
//
// The callback secret is held only as KMS envelopes. Nothing here is a plaintext secret.
type PlaybackAuth struct {
	JWTEnabled     bool
	JWTIssuer      string
	JWTAudiences   []string
	JWKSURL        string // empty when the tenant uses uploaded keys only
	JWTViewerClaim string

	CallbackEnabled bool
	CallbackURL     string

	// CallbackSecretEnvelope is the current secret's envelope (nil until the first rotation) and
	// CallbackSecretVersion its version (0 until the first rotation).
	CallbackSecretEnvelope []byte
	CallbackSecretVersion  int
	// The previous secret, kept for the overlap after a rotation. PrevVersion is 0 when none.
	CallbackSecretPrevEnvelope []byte
	CallbackSecretPrevVersion  int
	CallbackSecretRotatedAt    *time.Time

	UpdatedAt time.Time
}

// DefaultPlaybackAuth returns the configuration of a tenant that has none stored.
func DefaultPlaybackAuth() PlaybackAuth {
	return PlaybackAuth{JWTAudiences: []string{}, JWTViewerClaim: DefaultViewerClaim}
}

// PlaybackJWTKey is an uploaded public key. JWK is the canonical JSON of the public JWK.
type PlaybackJWTKey struct {
	Kid       string
	Alg       string
	JWK       []byte
	CreatedAt time.Time
}

func authFromRow(r dbgen.PlaybackAuth) PlaybackAuth {
	a := PlaybackAuth{
		JWTEnabled:                 r.JwtEnabled,
		JWTIssuer:                  r.JwtIssuer,
		JWTAudiences:               append([]string{}, r.JwtAudiences...),
		JWKSURL:                    strVal(r.JwtJwksUrl),
		JWTViewerClaim:             r.JwtViewerClaim,
		CallbackEnabled:            r.CallbackEnabled,
		CallbackURL:                strVal(r.CallbackUrl),
		CallbackSecretEnvelope:     slices.Clone(r.CallbackSecretEnvelope),
		CallbackSecretVersion:      int(r.CallbackSecretVersion),
		CallbackSecretPrevEnvelope: slices.Clone(r.CallbackSecretPrevEnvelope),
		CallbackSecretRotatedAt:    utcPtr(r.CallbackSecretRotatedAt),
		UpdatedAt:                  r.UpdatedAt.UTC(),
	}
	if r.CallbackSecretPrevVersion != nil {
		a.CallbackSecretPrevVersion = int(*r.CallbackSecretPrevVersion)
	}
	return a
}

// GetPlaybackAuth returns the tenant's configuration, or the defaults when it has none stored.
func (r *Repos) GetPlaybackAuth(ctx context.Context, tenantID id.TenantID) (PlaybackAuth, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return PlaybackAuth{}, err
	}
	row, err := r.q.GetPlaybackAuth(ctx, tid)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultPlaybackAuth(), nil
	}
	if err != nil {
		return PlaybackAuth{}, mapError(err)
	}
	return authFromRow(row), nil
}

// PutPlaybackAuthConfig replaces the configuration fields (not the callback secret). The caller
// validates first; the table's CHECK constraints are the backstop.
func (r *Repos) PutPlaybackAuthConfig(ctx context.Context, tenantID id.TenantID, a PlaybackAuth, at time.Time) (PlaybackAuth, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return PlaybackAuth{}, err
	}
	aud := a.JWTAudiences
	if aud == nil {
		aud = []string{}
	}
	row, err := r.q.UpsertPlaybackAuthConfig(ctx, dbgen.UpsertPlaybackAuthConfigParams{
		TenantID: tid, JwtEnabled: a.JWTEnabled, JwtIssuer: a.JWTIssuer, JwtAudiences: aud,
		JwtJwksUrl: strPtr(a.JWKSURL), JwtViewerClaim: a.JWTViewerClaim,
		CallbackEnabled: a.CallbackEnabled, CallbackUrl: strPtr(a.CallbackURL), At: at,
	})
	if err != nil {
		return PlaybackAuth{}, mapError(err)
	}
	return authFromRow(row), nil
}

// RotatePlaybackCallbackSecret stores envelope as the current secret with the given version and
// moves the previous current secret, if any, to "previous". version must be the current version
// plus one; otherwise (a concurrent rotation won) it returns a conflict and writes nothing.
func (r *Repos) RotatePlaybackCallbackSecret(ctx context.Context, tenantID id.TenantID, envelope []byte, version int, at time.Time) (PlaybackAuth, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return PlaybackAuth{}, err
	}
	if len(envelope) == 0 || version < 1 {
		return PlaybackAuth{}, errs.New(errs.InvalidRequest, "invalid callback secret")
	}
	row, err := r.q.RotatePlaybackCallbackSecret(ctx, dbgen.RotatePlaybackCallbackSecretParams{
		TenantID: tid, Envelope: envelope, Version: int32(version), At: at, //nolint:gosec // a small counter
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PlaybackAuth{}, errs.New(errs.Conflict, "The callback secret was rotated concurrently. Try again.")
	}
	if err != nil {
		return PlaybackAuth{}, mapError(err)
	}
	return authFromRow(row), nil
}

// LockPlaybackAuth takes a transaction-scoped advisory lock for one tenant's authorization
// configuration. Use it inside Tx before a read-modify-write.
func (r *Repos) LockPlaybackAuth(ctx context.Context, tenantID id.TenantID) error {
	if tenantID.IsZero() {
		return errs.New(errs.InvalidRequest, "a required identifier is missing")
	}
	return mapError(r.q.LockPlaybackAuth(ctx, "cipherframe.playback_auth:"+tenantID.String()))
}

// ListPlaybackJWTKeys returns the tenant's uploaded public keys, ordered by kid.
func (r *Repos) ListPlaybackJWTKeys(ctx context.Context, tenantID id.TenantID) ([]PlaybackJWTKey, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListPlaybackJWTKeys(ctx, tid)
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]PlaybackJWTKey, len(rows))
	for i, k := range rows {
		out[i] = PlaybackJWTKey{Kid: k.Kid, Alg: k.Alg, JWK: slices.Clone(k.Jwk), CreatedAt: k.CreatedAt.UTC()}
	}
	return out, nil
}

// PutPlaybackJWTKey stores or replaces the public key with the given kid, unless the tenant would
// then hold more than MaxPlaybackJWTKeys (a conflict). Call it inside Tx: it takes the tenant's
// authorization lock, so the count and the insert cannot interleave with another upload.
func (r *Repos) PutPlaybackJWTKey(ctx context.Context, tenantID id.TenantID, k PlaybackJWTKey, at time.Time) (PlaybackJWTKey, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return PlaybackJWTKey{}, err
	}
	if err := r.LockPlaybackAuth(ctx, tenantID); err != nil {
		return PlaybackJWTKey{}, err
	}
	n, err := r.q.CountPlaybackJWTKeysExcept(ctx, dbgen.CountPlaybackJWTKeysExceptParams{TenantID: tid, Kid: k.Kid})
	if err != nil {
		return PlaybackJWTKey{}, mapError(err)
	}
	if n >= MaxPlaybackJWTKeys {
		return PlaybackJWTKey{}, errs.New(errs.Conflict, "The tenant already has the maximum number of JWT keys.")
	}
	row, err := r.q.UpsertPlaybackJWTKey(ctx, dbgen.UpsertPlaybackJWTKeyParams{
		TenantID: tid, Kid: k.Kid, Alg: k.Alg, Jwk: k.JWK, At: at,
	})
	if err != nil {
		return PlaybackJWTKey{}, mapError(err)
	}
	return PlaybackJWTKey{Kid: row.Kid, Alg: row.Alg, JWK: slices.Clone(row.Jwk), CreatedAt: row.CreatedAt.UTC()}, nil
}

// DeletePlaybackJWTKey deletes the tenant's key with the given kid and reports whether it existed.
func (r *Repos) DeletePlaybackJWTKey(ctx context.Context, tenantID id.TenantID, kid string) (bool, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return false, err
	}
	n, err := r.q.DeletePlaybackJWTKey(ctx, dbgen.DeletePlaybackJWTKeyParams{TenantID: tid, Kid: kid})
	if err != nil {
		return false, mapError(err)
	}
	return n > 0, nil
}

// JWTIDHash is the SHA-256 of a JWT id: what playback_jwt_jti stores, so the table never holds the
// identifiers a tenant picks.
func JWTIDHash(jti string) []byte {
	h := sha256.Sum256([]byte(jti))
	return h[:]
}

// ClaimPlaybackJWTID records the JWT id as used by the tenant until expiresAt and reports whether
// this call was the first to use it. False means a replay.
func (r *Repos) ClaimPlaybackJWTID(ctx context.Context, tenantID id.TenantID, jti string, expiresAt time.Time) (bool, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return false, err
	}
	if jti == "" {
		return false, errs.New(errs.InvalidRequest, "a JWT id is required")
	}
	n, err := r.q.ClaimPlaybackJWTID(ctx, dbgen.ClaimPlaybackJWTIDParams{TenantID: tid, JtiHash: JWTIDHash(jti), ExpiresAt: expiresAt})
	if err != nil {
		return false, mapError(err)
	}
	return n == 1, nil
}

// SweepPlaybackJWTIDs deletes the JWT ids whose expiry is before the given time and returns how
// many it deleted.
func (r *Repos) SweepPlaybackJWTIDs(ctx context.Context, before time.Time) (int64, error) {
	n, err := r.q.SweepPlaybackJWTIDs(ctx, before)
	return n, mapError(err)
}
