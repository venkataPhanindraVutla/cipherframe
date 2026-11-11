package viewerauth

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
)

// JWT limits (ADR 0029). The asset_id claim and the 24 hour horizon are Cipherframe's additions to
// the ADR, described in docs/api.md.
const (
	// ClockSkew is the leeway applied to exp, nbf and iat.
	ClockSkew = 60 * time.Second
	// MaxJTIChars is the longest accepted jti.
	MaxJTIChars = 128
	// MaxTokenBytes is the longest accepted token. A real one is well under 2 KiB.
	MaxTokenBytes = 8 << 10
	// MaxLifetime is how far in the future a token's exp may be. The jti of a token is kept until
	// its exp, so an unbounded exp would be an unbounded row. A token that opens a playback
	// session is used within seconds; a day is generous.
	MaxLifetime = 24 * time.Hour
	// AssetClaim is the claim that binds a token to one asset.
	AssetClaim = "asset_id"
)

// Denial reasons. They are for the operator's debug log and the tests; the caller of the API only
// ever sees a generic 401.
const (
	ReasonMalformed   = "malformed"
	ReasonConfig      = "not_configured"
	ReasonUnknownKey  = "unknown_key"
	ReasonAlgorithm   = "algorithm"
	ReasonSignature   = "signature"
	ReasonIssuer      = "issuer"
	ReasonAudience    = "audience"
	ReasonExpired     = "expired"
	ReasonNotYetValid = "not_yet_valid"
	ReasonLifetime    = "lifetime"
	ReasonJTI         = "jti"
	ReasonAsset       = "asset"
	ReasonViewer      = "viewer"
)

// DenyError is a refusal. Reason is one of the Reason constants.
type DenyError struct{ Reason string }

func (e *DenyError) Error() string { return "viewerauth: denied (" + e.Reason + ")" }

func deny(reason string) error { return &DenyError{Reason: reason} }

// ReasonOf returns the reason of a DenyError, or "" for any other error.
func ReasonOf(err error) string {
	var d *DenyError
	if errors.As(err, &d) {
		return d.Reason
	}
	return ""
}

// JWTConfig is the part of a tenant's configuration that verification needs.
type JWTConfig struct {
	Issuer      string
	Audiences   []string
	JWKSURL     string // empty: uploaded keys only
	ViewerClaim string
	// Uploaded are the tenant's uploaded public keys by kid.
	Uploaded map[string]PublicKey
}

// Verified is what a valid token yields.
type Verified struct {
	Viewer string
	JTI    string
	// Expiry is the token's exp. Record the jti until Expiry + ClockSkew.
	Expiry time.Time
}

// VerifierOptions configure a Verifier.
type VerifierOptions struct {
	// Client fetches JWKS documents. Required.
	Client *outbound.Client
	// ValidateViewer checks the viewer ID taken from the token. Required.
	ValidateViewer func(string) error
	// Now defaults to time.Now.
	Now func() time.Time
}

// Verifier verifies viewers' JWTs. Safe for concurrent use.
type Verifier struct {
	jwks     *jwksCache
	validate func(string) error
	now      func() time.Time
}

// NewVerifier returns a Verifier.
func NewVerifier(o VerifierOptions) (*Verifier, error) {
	if o.Client == nil || o.ValidateViewer == nil {
		return nil, errors.New("viewerauth: a client and a viewer validator are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Verifier{jwks: newJWKSCache(o.Client, o.Now), validate: o.ValidateViewer, now: o.Now}, nil
}

// Verify checks raw, a JWT from a viewer's browser, for the tenant and the asset the viewer asks
// to play. It returns a *DenyError for every refusal.
//
// The order matters: the algorithm allowlist is applied by the parser, before any key is chosen,
// so "none" and the HMAC algorithms are refused outright and a token can never be verified with
// a public key used as an HMAC secret. The key is found by kid (uploaded keys first, then the
// JWKS) and may be used only with the algorithm it was registered or derived for. Only after the
// signature verifies are the claims read:
//
//   - iss equals the configured issuer, and aud contains one of the configured audiences;
//   - exp is present and in the future, nbf and iat (if present) are not in the future, each with
//     60 seconds of leeway, and exp is no more than 24 hours away;
//   - jti is present and at most 128 characters (the caller records it to make it single-use);
//   - the asset_id claim equals the asset the viewer asked for;
//   - the configured viewer claim is a string that is a valid viewer ID.
func (v *Verifier) Verify(ctx context.Context, tenant string, cfg JWTConfig, raw, assetID string) (Verified, error) {
	if cfg.Issuer == "" || len(cfg.Audiences) == 0 || cfg.ViewerClaim == "" {
		return Verified{}, deny(ReasonConfig)
	}
	if raw == "" || len(raw) > MaxTokenBytes {
		return Verified{}, deny(ReasonMalformed)
	}
	tok, err := jwt.ParseSigned(raw, Algorithms)
	if err != nil || len(tok.Headers) != 1 {
		return Verified{}, deny(ReasonMalformed)
	}
	hdr := tok.Headers[0]
	if hdr.KeyID == "" {
		return Verified{}, deny(ReasonUnknownKey)
	}

	key, ok := cfg.Uploaded[hdr.KeyID]
	if !ok && cfg.JWKSURL != "" {
		key, ok = v.jwks.lookup(ctx, tenant, cfg.JWKSURL, hdr.KeyID)
	}
	if !ok {
		return Verified{}, deny(ReasonUnknownKey)
	}
	if hdr.Algorithm != key.Alg {
		return Verified{}, deny(ReasonAlgorithm)
	}

	// The signature is verified by the first call. The second only decodes the registered claims
	// from the same, now verified, payload, so a claim of the wrong type is "malformed" and not
	// "signature".
	var all map[string]any
	if err := tok.Claims(key.Key, &all); err != nil {
		return Verified{}, deny(ReasonSignature)
	}
	var std jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&std); err != nil {
		return Verified{}, deny(ReasonMalformed)
	}

	now := v.now()
	err = std.ValidateWithLeeway(jwt.Expected{Issuer: cfg.Issuer, AnyAudience: cfg.Audiences, Time: now}, ClockSkew)
	switch {
	case errors.Is(err, jwt.ErrInvalidIssuer):
		return Verified{}, deny(ReasonIssuer)
	case errors.Is(err, jwt.ErrInvalidAudience):
		return Verified{}, deny(ReasonAudience)
	case errors.Is(err, jwt.ErrExpired):
		return Verified{}, deny(ReasonExpired)
	case errors.Is(err, jwt.ErrNotValidYet), errors.Is(err, jwt.ErrIssuedInTheFuture):
		return Verified{}, deny(ReasonNotYetValid)
	case err != nil:
		return Verified{}, deny(ReasonMalformed)
	}
	// go-jose treats a missing exp as "no expiry"; Cipherframe requires one.
	if std.Expiry == nil {
		return Verified{}, deny(ReasonExpired)
	}
	exp := std.Expiry.Time()
	if exp.After(now.Add(MaxLifetime)) {
		return Verified{}, deny(ReasonLifetime)
	}
	if std.ID == "" || utf8.RuneCountInString(std.ID) > MaxJTIChars {
		return Verified{}, deny(ReasonJTI)
	}
	if s, ok := all[AssetClaim].(string); !ok || s != assetID {
		return Verified{}, deny(ReasonAsset)
	}
	viewer, ok := all[cfg.ViewerClaim].(string)
	if !ok || v.validate(viewer) != nil {
		return Verified{}, deny(ReasonViewer)
	}
	return Verified{Viewer: viewer, JTI: std.ID, Expiry: exp}, nil
}
