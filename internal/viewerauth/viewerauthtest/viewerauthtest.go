// Package viewerauthtest holds helpers for tests of the JWT and callback authorization of playback
// sessions: key generation, token signing (including deliberately broken tokens) and a reference
// Standard Webhooks verifier written from the specification, independently of package viewerauth.
//
// Nothing here is for production code.
package viewerauthtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Key is a signing key pair with its key ID and the algorithm it is meant for.
type Key struct {
	Kid     string
	Alg     string // EdDSA, ES256 or RS256
	Private crypto.Signer
}

var (
	rsaOnce sync.Once
	rsaKeys []*rsa.PrivateKey // pre-generated: RSA key generation is slow
	rsaNext int
	rsaMu   sync.Mutex
)

// NewKey generates a key for alg ("EdDSA", "ES256" or "RS256") with the given kid.
func NewKey(t testing.TB, alg, kid string) Key {
	t.Helper()
	var s crypto.Signer
	var err error
	switch alg {
	case "EdDSA":
		_, s, err = ed25519.GenerateKey(rand.Reader)
	case "ES256":
		s, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "RS256":
		s = nextRSA(t, 2048)
	default:
		t.Fatalf("viewerauthtest: unknown alg %q", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return Key{Kid: kid, Alg: alg, Private: s}
}

func nextRSA(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	if bits != 2048 {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	rsaOnce.Do(func() {
		for range 4 {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			rsaKeys = append(rsaKeys, k)
		}
	})
	rsaMu.Lock()
	defer rsaMu.Unlock()
	k := rsaKeys[rsaNext%len(rsaKeys)]
	rsaNext++
	return k
}

// RSAKeyBits returns an RS256 key of the given size (used for the too-short key tests).
func RSAKeyBits(t testing.TB, kid string, bits int) Key {
	t.Helper()
	return Key{Kid: kid, Alg: "RS256", Private: nextRSA(t, bits)}
}

// PublicJWK returns the public JWK JSON with kid and alg set.
func (k Key) PublicJWK(t testing.TB) []byte {
	t.Helper()
	b, err := jose.JSONWebKey{Key: k.Private.Public(), KeyID: k.Kid, Algorithm: k.Alg, Use: "sig"}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// PrivateJWK returns the private JWK JSON (for the "private key is refused" tests).
func (k Key) PrivateJWK(t testing.TB) []byte {
	t.Helper()
	b, err := jose.JSONWebKey{Key: k.Private, KeyID: k.Kid, Algorithm: k.Alg, Use: "sig"}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// JWKS returns a JWKS document with the public keys of keys.
func JWKS(t testing.TB, keys ...Key) []byte {
	t.Helper()
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	for _, k := range keys {
		set.Keys = append(set.Keys, k.PublicJWK(t))
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Sign signs claims with the key. headers adds or overrides protected header members ("kid" and
// "alg" are set from the key).
func (k Key) Sign(t testing.TB, claims map[string]any, headers ...map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.Kid)
	for _, h := range headers {
		for name, v := range h {
			opts = opts.WithHeader(jose.HeaderKey(name), v)
		}
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(k.Alg), Key: k.Private}, opts)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// UnsignedToken returns a token whose header says "alg": "none" and has an empty signature.
func UnsignedToken(t testing.TB, kid string, claims map[string]any) string {
	t.Helper()
	return b64(mustJSON(t, map[string]any{"alg": "none", "typ": "JWT", "kid": kid})) + "." + b64(mustJSON(t, claims)) + "."
}

// HS256Token returns a token signed with HMAC-SHA256 under secret. With the bytes of a public key
// as the secret it is the classic algorithm-confusion attack.
func HS256Token(t testing.TB, kid string, secret []byte, claims map[string]any) string {
	t.Helper()
	signing := b64(mustJSON(t, map[string]any{"alg": "HS256", "typ": "JWT", "kid": kid})) + "." + b64(mustJSON(t, claims))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signing))
	return signing + "." + b64(mac.Sum(nil))
}

// Claims returns a valid claim set for the tenant's issuer and audience, an asset and a viewer,
// expiring in ten minutes, with a fresh jti. Tests overwrite the member they want to break.
func Claims(now time.Time, issuer, audience, assetID, viewer string) map[string]any {
	return map[string]any{
		"iss": issuer, "aud": audience, "sub": viewer, "asset_id": assetID,
		"iat": now.Add(-time.Second).Unix(), "nbf": now.Add(-time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(), "jti": randomID(),
	}
}

func randomID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "test-fixture-jti-" + b64(b)
}

// VerifyWebhook is a reference Standard Webhooks verifier (https://www.standardwebhooks.com),
// written from the specification and sharing no code with package viewerauth. secret is the text
// form ("whsec_" and base64). It checks the three headers, the timestamp tolerance, and that at
// least one "v1,<base64>" signature in the space-separated list matches HMAC-SHA256 over
// "<id>.<timestamp>.<body>". It returns the number of signatures present.
func VerifyWebhook(secret string, h http.Header, body []byte, now time.Time, tolerance time.Duration) (signatures int, err error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		return 0, err
	}
	id, ts, sigHdr := h.Get("webhook-id"), h.Get("webhook-timestamp"), h.Get("webhook-signature")
	if id == "" || ts == "" || sigHdr == "" {
		return 0, errors.New("missing webhook headers")
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return 0, errors.New("bad timestamp")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > tolerance || d < -tolerance {
		return 0, errors.New("timestamp outside the tolerance")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	ok := false
	for _, part := range strings.Split(sigHdr, " ") {
		signatures++
		ver, enc, found := strings.Cut(part, ",")
		if !found || ver != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(enc)
		if err == nil && hmac.Equal(got, want) {
			ok = true
		}
	}
	if !ok {
		return signatures, errors.New("no signature matches")
	}
	return signatures, nil
}
