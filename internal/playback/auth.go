package playback

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
)

// Audit actions written when a tenant's playback authorization changes (the audit_events.action
// column). The events name the tenant, the kid or nothing else: never a key, a URL or a secret.
const (
	AuditAuthUpdate       = "playback_auth.update"
	AuditAuthKeyPut       = "playback_auth.jwt_key.put"
	AuditAuthKeyDelete    = "playback_auth.jwt_key.delete"
	AuditAuthSecretRotate = "playback_auth.callback_secret.rotate" //nolint:gosec // an audit action name, not a credential
)

// Limits of the authorization configuration.
const (
	MaxAudiences   = 10
	maxIssuerChars = 512
	maxAudChars    = 256
	maxURLChars    = 2048
	maxClaimChars  = 64
	maxKidChars    = 128
)

var (
	reKid   = regexp.MustCompile(`^[A-Za-z0-9._~:-]{1,128}$`)
	reClaim = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

// ValidKid reports whether kid is an acceptable key ID: 1 to 128 characters from
// letters, digits and `._~:-`.
func ValidKid(kid string) bool { return reKid.MatchString(kid) }

// AuthView is a tenant's authorization configuration for the admin API: the configuration, the
// state of the callback secret (never the secret) and the uploaded keys.
type AuthView struct {
	Config db.PlaybackAuth
	Keys   []db.PlaybackJWTKey
	// SecretConfigured is true once the callback secret has been rotated at least once.
	SecretConfigured bool
	// PreviousSecretValidUntil is set while the previous secret still signs callbacks.
	PreviousSecretValidUntil *time.Time
}

func authView(a db.PlaybackAuth, keys []db.PlaybackJWTKey, now time.Time) AuthView {
	v := AuthView{Config: a, Keys: keys, SecretConfigured: a.CallbackSecretVersion > 0}
	if until, ok := PreviousSecretValidUntil(a, now); ok {
		v.PreviousSecretValidUntil = &until
	}
	return v
}

// PreviousSecretValidUntil reports whether the previous callback secret still signs at now (within
// 24 hours of the rotation that replaced it) and until when.
func PreviousSecretValidUntil(a db.PlaybackAuth, now time.Time) (time.Time, bool) {
	if a.CallbackSecretPrevVersion == 0 || len(a.CallbackSecretPrevEnvelope) == 0 || a.CallbackSecretRotatedAt == nil {
		return time.Time{}, false
	}
	until := a.CallbackSecretRotatedAt.Add(viewerauth.PreviousSecretWindow)
	return until, now.Before(until)
}

// ValidateAuthConfig checks the configuration fields of in and returns one entry per problem.
// Messages never quote submitted values. The checks that need stored state (a callback secret
// exists before callbacks are enabled, JWT keys exist before JWT is enabled) are made by PutAuth.
func ValidateAuthConfig(in db.PlaybackAuth) []errs.FieldError {
	var out []errs.FieldError
	bad := func(field, msg string) { out = append(out, errs.FieldError{Field: field, Message: msg}) }
	printable := func(s string) bool {
		if !utf8.ValidString(s) {
			return false
		}
		for _, r := range s {
			if !unicode.IsPrint(r) {
				return false
			}
		}
		return true
	}

	if in.JWTIssuer == "" {
		if in.JWTEnabled {
			bad("jwt_issuer", "is required when jwt_enabled is true")
		}
	} else if utf8.RuneCountInString(in.JWTIssuer) > maxIssuerChars || !printable(in.JWTIssuer) {
		bad("jwt_issuer", "must be at most 512 printable characters")
	}
	if len(in.JWTAudiences) > MaxAudiences {
		bad("jwt_audiences", "must list at most 10 audiences")
	}
	if in.JWTEnabled && len(in.JWTAudiences) == 0 {
		bad("jwt_audiences", "must list at least one audience when jwt_enabled is true")
	}
	seen := map[string]bool{}
	for i, a := range in.JWTAudiences {
		field := "jwt_audiences[" + strconv.Itoa(i) + "]"
		switch {
		case a == "" || utf8.RuneCountInString(a) > maxAudChars || !printable(a):
			bad(field, "must be 1 to 256 printable characters")
		case seen[a]:
			bad(field, "must not repeat another entry")
		}
		seen[a] = true
	}
	if in.JWKSURL != "" {
		if len(in.JWKSURL) > maxURLChars || outbound.CheckURL(in.JWKSURL) != nil {
			bad("jwt_jwks_url", "must be an https URL with a public host, at most 2048 characters, without credentials or a fragment")
		}
	}
	if !reClaim.MatchString(in.JWTViewerClaim) {
		bad("jwt_viewer_claim", "must be 1 to 64 characters from letters, digits and _.:-")
	}
	if in.CallbackURL == "" {
		if in.CallbackEnabled {
			bad("callback_url", "is required when callback_enabled is true")
		}
	} else if len(in.CallbackURL) > maxURLChars || outbound.CheckURL(in.CallbackURL) != nil {
		bad("callback_url", "must be an https URL with a public host, at most 2048 characters, without credentials or a fragment")
	}
	return out
}

// GetAuth returns the tenant's authorization configuration: the stored one, or the defaults.
func (s *Service) GetAuth(ctx context.Context, tenantID id.TenantID) (AuthView, error) {
	a, err := s.repos.GetPlaybackAuth(ctx, tenantID)
	if err != nil {
		return AuthView{}, err
	}
	keys, err := s.repos.ListPlaybackJWTKeys(ctx, tenantID)
	if err != nil {
		return AuthView{}, err
	}
	return authView(a, keys, s.now()), nil
}

// PutAuth validates and replaces the tenant's authorization configuration (not its callback secret
// and keys) and records an audit event. Callbacks cannot be enabled before a callback secret
// exists, and JWT cannot be enabled with neither a JWKS URL nor an uploaded key.
func (s *Service) PutAuth(ctx context.Context, tenantID id.TenantID, actor auth.Actor, in db.PlaybackAuth) (AuthView, error) {
	if fields := ValidateAuthConfig(in); len(fields) > 0 {
		return AuthView{}, errs.Invalid("The playback authorization settings are invalid.", fields)
	}
	var view AuthView
	err := db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		if err := tx.LockPlaybackAuth(ctx, tenantID); err != nil {
			return err
		}
		cur, err := tx.GetPlaybackAuth(ctx, tenantID)
		if err != nil {
			return err
		}
		keys, err := tx.ListPlaybackJWTKeys(ctx, tenantID)
		if err != nil {
			return err
		}
		var fields []errs.FieldError
		if in.CallbackEnabled && cur.CallbackSecretVersion == 0 {
			fields = append(fields, errs.FieldError{Field: "callback_enabled", Message: "requires a callback secret: rotate it first"})
		}
		if in.JWTEnabled && in.JWKSURL == "" && len(keys) == 0 {
			fields = append(fields, errs.FieldError{Field: "jwt_enabled", Message: "requires a jwt_jwks_url or at least one uploaded key"})
		}
		if len(fields) > 0 {
			return errs.Invalid("The playback authorization settings are invalid.", fields)
		}
		now := s.now().UTC()
		out, err := tx.PutPlaybackAuthConfig(ctx, tenantID, in, now)
		if err != nil {
			return err
		}
		if err := s.auditAuth(ctx, tx, tenantID, actor, AuditAuthUpdate, tenantID.String()); err != nil {
			return err
		}
		view = authView(out, keys, now)
		return nil
	})
	return view, err
}

func (s *Service) auditAuth(ctx context.Context, tx *db.Repos, tenantID id.TenantID, actor auth.Actor, action, target string) error {
	_, err := tx.InsertAuditEvent(ctx, db.NewAuditEvent{
		TenantID: tenantID, ClientID: actor.ClientID, APIKeyID: actor.KeyID,
		Action: action, Target: target, RequestID: actor.RequestID,
	})
	return err
}

// PutJWTKey validates and stores a public JWK for the tenant under kid (replacing a key with the
// same kid) and records an audit event. See viewerauth.ParseUploadedJWK for what is refused.
func (s *Service) PutJWTKey(ctx context.Context, tenantID id.TenantID, actor auth.Actor, kid string, jwk []byte) (db.PlaybackJWTKey, error) {
	if !ValidKid(kid) {
		return db.PlaybackJWTKey{}, errs.Invalid("The request is invalid.", []errs.FieldError{{Field: "kid", Message: "must be 1 to 128 characters from letters, digits and ._~:-"}})
	}
	pk, err := viewerauth.ParseUploadedJWK(kid, jwk)
	if err != nil {
		var ke *viewerauth.ErrKey
		if errors.As(err, &ke) {
			return db.PlaybackJWTKey{}, errs.Invalid("The JWK is invalid.", []errs.FieldError{{Field: "jwk", Message: ke.Msg}})
		}
		return db.PlaybackJWTKey{}, err
	}
	var out db.PlaybackJWTKey
	err = db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		var err error
		if out, err = tx.PutPlaybackJWTKey(ctx, tenantID, db.PlaybackJWTKey{Kid: kid, Alg: pk.Alg, JWK: pk.JWK}, s.now().UTC()); err != nil {
			return err
		}
		return s.auditAuth(ctx, tx, tenantID, actor, AuditAuthKeyPut, kid)
	})
	return out, err
}

// DeleteJWTKey deletes the tenant's key with the given kid and records an audit event. A kid that
// does not exist is not_found.
func (s *Service) DeleteJWTKey(ctx context.Context, tenantID id.TenantID, actor auth.Actor, kid string) error {
	if !ValidKid(kid) {
		return errs.New(errs.NotFound, "No such JWT key.")
	}
	return db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		ok, err := tx.DeletePlaybackJWTKey(ctx, tenantID, kid)
		if err != nil {
			return err
		}
		if !ok {
			return errs.New(errs.NotFound, "No such JWT key.")
		}
		return s.auditAuth(ctx, tx, tenantID, actor, AuditAuthKeyDelete, kid)
	})
}

// RotatedSecret is the result of RotateCallbackSecret. Secret is shown once and is redacted in
// every printed form.
type RotatedSecret struct {
	Secret  config.Secret // "whsec_" and base64 of 32 random bytes
	Version int
	// PreviousValidUntil is when the previous secret stops signing; nil on the first rotation.
	PreviousValidUntil *time.Time
}

// RotateCallbackSecret generates a new callback secret, stores it wrapped by the key provider
// (bound to the tenant, the purpose and the new version) and returns it once. The secret it
// replaces keeps signing callbacks, next to the new one, for 24 hours. It needs the key provider:
// without one it is dependency_unavailable. A provider failure leaves the stored secret as it was.
func (s *Service) RotateCallbackSecret(ctx context.Context, tenantID id.TenantID, actor auth.Actor) (RotatedSecret, error) {
	if s.secrets == nil {
		return RotatedSecret{}, errs.New(errs.DependencyUnavailable, "Key management is not available.")
	}
	cur, err := s.repos.GetPlaybackAuth(ctx, tenantID)
	if err != nil {
		return RotatedSecret{}, err
	}
	version := cur.CallbackSecretVersion + 1
	secret, err := viewerauth.GenerateSecret()
	if err != nil {
		return RotatedSecret{}, errs.Wrap(errs.InternalError, "An internal error occurred.", err)
	}
	defer clear(secret)
	envelope, err := s.secrets.Seal(ctx, tenantID, version, secret)
	if err != nil {
		return RotatedSecret{}, kms.ToAppError(err)
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var out db.PlaybackAuth
	// The rotation statement only applies when version is still the next one, so a concurrent
	// rotation makes this one a conflict instead of two secrets sharing a version. No KMS call is
	// made inside the transaction.
	err = db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		var err error
		if out, err = tx.RotatePlaybackCallbackSecret(ctx, tenantID, envelope, version, now); err != nil {
			return err
		}
		return s.auditAuth(ctx, tx, tenantID, actor, AuditAuthSecretRotate, tenantID.String())
	})
	if err != nil {
		return RotatedSecret{}, err
	}
	res := RotatedSecret{Secret: config.NewSecret(viewerauth.FormatSecret(secret)), Version: out.CallbackSecretVersion}
	if until, ok := PreviousSecretValidUntil(out, now); ok {
		res.PreviousValidUntil = &until
	}
	return res, nil
}
