package token

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

var t0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func key(fill byte, n int) []byte { return bytes.Repeat([]byte{fill}, n) }

func testKeyring(t testing.TB, current int, versions ...int) *Keyring {
	t.Helper()
	m := map[int][]byte{}
	for _, v := range versions {
		m[v] = append([]byte("test-fixture-"), key("abcdefghijklmnopqrstuvwxyz"[v%26], 24)...)
	}
	k, err := NewKeyring(m, current)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func session(t testing.TB) string {
	t.Helper()
	s, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	return s.String()
}

func claims(t testing.TB, sc Scope) Claims {
	t.Helper()
	return Claims{
		SessionID: session(t), AssetID: id.New[id.AssetKind]().String(), TenantID: id.New[id.TenantKind]().String(),
		Scopes: sc, IssuedAt: t0, Expiry: t0.Add(10 * time.Minute),
	}
}

func isInvalid(err error) bool { return errors.Is(err, ErrInvalid) }

func TestRoundTrip(t *testing.T) {
	k := testKeyring(t, 1, 1)
	for _, sc := range []Scope{ScopeManifest, ScopeKey, ScopeSegment, ScopeManifest | ScopeSegment, allScopes} {
		c := claims(t, sc)
		tok, err := k.Sign(c)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(tok, "v1.") || strings.Count(tok, ".") != 3 {
			t.Fatalf("unexpected shape for %s", sc)
		}
		got, err := k.Verify(tok, t0.Add(time.Minute), sc, c.AssetID)
		if err != nil {
			t.Fatalf("%s: %v", sc, err)
		}
		if got != c {
			t.Fatalf("%s: claims changed: %+v vs %+v", sc, got, c)
		}
		// Each single scope verifies exactly when the token carries it.
		for _, one := range []Scope{ScopeManifest, ScopeKey, ScopeSegment} {
			_, err := k.Verify(tok, t0, one, c.AssetID)
			if (err == nil) != sc.Has(one) {
				t.Fatalf("%s need %s: err=%v", sc, one, err)
			}
		}
	}
}

func TestVerifyFailures(t *testing.T) {
	k := testKeyring(t, 1, 1)
	c := claims(t, ScopeManifest|ScopeSegment)
	tok, err := k.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	flip := func(s string) string {
		b := []byte(s)
		if b[0] == 'A' {
			b[0] = 'B'
		} else {
			b[0] = 'A'
		}
		return string(b)
	}
	join := func(p ...string) string { return strings.Join(p, ".") }

	// signRaw signs an arbitrary payload text with key 1, so the MAC is valid.
	signRaw := func(body string) string {
		signed := "v1." + base64.RawURLEncoding.EncodeToString([]byte(body)) + ".1"
		return signed + "." + base64.RawURLEncoding.EncodeToString(mac(k.keys[1], signed))
	}
	exp := fmt.Sprint(t0.Add(time.Hour).Unix())
	good := fmt.Sprintf(`{"s":%q,"a":%q,"n":%q,"m":1,"i":%d,"e":%s}`, c.SessionID, c.AssetID, c.TenantID, t0.Unix(), exp)
	if _, err := k.Verify(signRaw(good), t0, ScopeManifest, c.AssetID); err != nil {
		t.Fatalf("control token rejected: %v", err)
	}

	tests := []struct {
		name  string
		tok   string
		now   time.Time
		need  Scope
		asset string
	}{
		{"wrong scope", tok, t0, ScopeKey, c.AssetID},
		{"partly wrong scope", tok, t0, ScopeKey | ScopeSegment, c.AssetID},
		{"empty need", tok, t0, 0, c.AssetID},
		{"unknown need bit", tok, t0, 1 << 5, c.AssetID},
		{"wrong asset", tok, t0, ScopeManifest, id.New[id.AssetKind]().String()},
		{"empty asset", tok, t0, ScopeManifest, ""},
		{"expired", tok, t0.Add(11 * time.Minute), ScopeManifest, c.AssetID},
		{"expiry instant is expired", tok, c.Expiry, ScopeManifest, c.AssetID},
		{"tampered payload", join(parts[0], flip(parts[1]), parts[2], parts[3]), t0, ScopeManifest, c.AssetID},
		{"tampered kid", join(parts[0], parts[1], "2", parts[3]), t0, ScopeManifest, c.AssetID},
		{"tampered mac", join(parts[0], parts[1], parts[2], flip(parts[3])), t0, ScopeManifest, c.AssetID},
		{"unknown kid", join(parts[0], parts[1], "9", parts[3]), t0, ScopeManifest, c.AssetID},
		{"non-numeric kid", join(parts[0], parts[1], "x", parts[3]), t0, ScopeManifest, c.AssetID},
		{"leading-zero kid", join(parts[0], parts[1], "01", parts[3]), t0, ScopeManifest, c.AssetID},
		{"non-v1 prefix", join("v2", parts[1], parts[2], parts[3]), t0, ScopeManifest, c.AssetID},
		{"empty prefix", join("", parts[1], parts[2], parts[3]), t0, ScopeManifest, c.AssetID},
		{"truncated parts", join(parts[0], parts[1], parts[2]), t0, ScopeManifest, c.AssetID},
		{"extra part", tok + ".AAAA", t0, ScopeManifest, c.AssetID},
		{"truncated mac", tok[:len(tok)-4], t0, ScopeManifest, c.AssetID},
		{"empty token", "", t0, ScopeManifest, c.AssetID},
		{"dots only", "...", t0, ScopeManifest, c.AssetID},
		{"overlong", tok + strings.Repeat("A", MaxTokenLen), t0, ScopeManifest, c.AssetID},
		{"unknown json field", signRaw(strings.Replace(good, `"m":1`, `"m":1,"x":1`, 1)), t0, ScopeManifest, c.AssetID},
		{"trailing json", signRaw(good + " {}"), t0, ScopeManifest, c.AssetID},
		{"not json", signRaw("nope"), t0, ScopeManifest, c.AssetID},
		{"zero scope in payload", signRaw(strings.Replace(good, `"m":1`, `"m":0`, 1)), t0, ScopeManifest, c.AssetID},
		{"unknown scope bit in payload", signRaw(strings.Replace(good, `"m":1`, `"m":9`, 1)), t0, ScopeManifest, c.AssetID},
		{"empty tenant in payload", signRaw(strings.Replace(good, c.TenantID, "", 1)), t0, ScopeManifest, c.AssetID},
		{"empty session in payload", signRaw(strings.Replace(good, c.SessionID, "", 1)), t0, ScopeManifest, c.AssetID},
		{"expiry before issue", signRaw(strings.Replace(good, exp, "1", 1)), t0, ScopeManifest, c.AssetID},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := k.Verify(tc.tok, tc.now, tc.need, tc.asset)
			if !isInvalid(err) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			if got != (Claims{}) {
				t.Fatal("claims returned with an error")
			}
			if tc.tok != "" && strings.Contains(err.Error(), tc.tok) {
				t.Fatal("error contains the token")
			}
		})
	}
}

func TestEveryFailureIsOneError(t *testing.T) {
	k := testKeyring(t, 1, 1)
	c := claims(t, ScopeKey)
	tok, _ := k.Sign(c)
	_, e1 := k.Verify(tok, t0.Add(time.Hour), ScopeKey, c.AssetID) // expired
	_, e2 := k.Verify(tok, t0, ScopeSegment, c.AssetID)            // scope
	_, e3 := k.Verify("garbage", t0, ScopeKey, c.AssetID)          // malformed
	if !errors.Is(e1, ErrInvalid) || !errors.Is(e2, ErrInvalid) || !errors.Is(e3, ErrInvalid) ||
		e1.Error() != e2.Error() || e2.Error() != e3.Error() {
		t.Fatal("failures are distinguishable")
	}
	var ee *errs.Error
	if !errors.As(e1, &ee) || ee.Code != errs.Unauthenticated {
		t.Fatalf("want errs.Unauthenticated, got %v", e1)
	}
	if strings.Contains(e1.Error(), tok) || strings.Contains(e1.Error(), c.SessionID) {
		t.Fatal("error leaks data")
	}
}

func TestRotation(t *testing.T) {
	old := testKeyring(t, 1, 1)
	c := claims(t, ScopeSegment)
	oldTok, err := old.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	rotated := testKeyring(t, 2, 1, 2)
	if _, err := rotated.Verify(oldTok, t0, ScopeSegment, c.AssetID); err != nil {
		t.Fatalf("old kid after rotation: %v", err)
	}
	newTok, err := rotated.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Split(newTok, ".")[2]; got != "2" {
		t.Fatalf("new tokens use kid %q", got)
	}
	if _, err := rotated.Verify(newTok, t0, ScopeSegment, c.AssetID); err != nil {
		t.Fatal(err)
	}
	// Once the old key is removed, its tokens stop verifying.
	retired := testKeyring(t, 2, 2)
	if _, err := retired.Verify(oldTok, t0, ScopeSegment, c.AssetID); !isInvalid(err) {
		t.Fatalf("retired key still verifies: %v", err)
	}
	// The old keyring does not know the new key.
	if _, err := old.Verify(newTok, t0, ScopeSegment, c.AssetID); !isInvalid(err) {
		t.Fatalf("unknown kid verified: %v", err)
	}
	// A different secret under the same kid does not verify.
	other, _ := NewKeyring(map[int][]byte{1: key('z', 32)}, 1)
	if _, err := other.Verify(oldTok, t0, ScopeSegment, c.AssetID); !isInvalid(err) {
		t.Fatalf("wrong secret verified: %v", err)
	}
}

func TestNewKeyringValidation(t *testing.T) {
	tests := []struct {
		name string
		keys map[int][]byte
		cur  int
	}{
		{"none", nil, 1},
		{"short key", map[int][]byte{1: key('a', 31)}, 1},
		{"zero version", map[int][]byte{0: key('a', 32)}, 0},
		{"negative version", map[int][]byte{-1: key('a', 32)}, -1},
		{"current missing", map[int][]byte{1: key('a', 32)}, 2},
		{"one short among several", map[int][]byte{1: key('a', 32), 2: key('b', 5)}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewKeyring(tc.keys, tc.cur)
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), "aaaa") || strings.Contains(err.Error(), "bbbb") {
				t.Fatal("error leaks key bytes")
			}
		})
	}
	if _, err := NewKeyring(map[int][]byte{1: key('a', 32)}, 1); err != nil {
		t.Fatalf("32 bytes rejected: %v", err)
	}
	// The keyring owns its keys.
	src := key('a', 32)
	k, _ := NewKeyring(map[int][]byte{1: src}, 1)
	c := claims(t, ScopeKey)
	tok, _ := k.Sign(c)
	clear(src)
	if _, err := k.Verify(tok, t0, ScopeKey, c.AssetID); err != nil {
		t.Fatalf("keyring aliases caller memory: %v", err)
	}
}

func TestSignRejectsBadClaims(t *testing.T) {
	k := testKeyring(t, 1, 1)
	good := claims(t, ScopeKey)
	tests := []struct {
		name string
		mod  func(*Claims)
	}{
		{"empty session", func(c *Claims) { c.SessionID = "" }},
		{"long session", func(c *Claims) { c.SessionID = strings.Repeat("s", 200) }},
		{"empty asset", func(c *Claims) { c.AssetID = "" }},
		{"no scope", func(c *Claims) { c.Scopes = 0 }},
		{"unknown scope", func(c *Claims) { c.Scopes = 1 << 4 }},
		{"expiry equals issue", func(c *Claims) { c.Expiry = c.IssuedAt }},
		{"expiry before issue", func(c *Claims) { c.Expiry = c.IssuedAt.Add(-time.Second) }},
		{"zero times", func(c *Claims) { c.IssuedAt, c.Expiry = time.Time{}, time.Time{} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.mod(&c)
			tok, err := k.Sign(c)
			if err == nil || tok != "" {
				t.Fatal("signed bad claims")
			}
			if strings.Contains(err.Error(), good.SessionID) {
				t.Fatal("error leaks claims")
			}
		})
	}
}

func TestTokenLengthFitsCap(t *testing.T) {
	k := testKeyring(t, 123456789, 123456789)
	c := claims(t, allScopes)
	tok, err := k.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) > MaxTokenLen/2 {
		t.Fatalf("typical token is %d bytes", len(tok))
	}
	c.SessionID = strings.Repeat("s", maxIDLen)
	c.AssetID = strings.Repeat("a", maxIDLen)
	if tok, err = k.Sign(c); err != nil || len(tok) > MaxTokenLen {
		t.Fatalf("max-size claims: %d bytes, %v", len(tok), err)
	}
}

func TestNilKeyringAndRedaction(t *testing.T) {
	var nilK *Keyring
	if _, err := nilK.Verify("x", t0, ScopeKey, "a"); !isInvalid(err) {
		t.Fatal("nil keyring verified")
	}
	k, _ := NewKeyring(map[int][]byte{1: []byte("test-fixture-" + strings.Repeat("q", 24))}, 1)
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("k", "keyring", k)
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%+v %#v %v %x", k, k, k, k), buf.String()} {
		if strings.Contains(s, "qqqq") || strings.Contains(s, "test-fixture") {
			t.Fatalf("keyring leaks key: %s", s)
		}
	}
}

func TestScopeString(t *testing.T) {
	for sc, want := range map[Scope]string{
		0: "none", ScopeManifest: "manifest", ScopeKey | ScopeSegment: "key|segment", allScopes: "manifest|key|segment",
	} {
		if got := sc.String(); got != want {
			t.Errorf("%d: %q, want %q", sc, got, want)
		}
	}
}

func FuzzVerify(f *testing.F) {
	k := testKeyring(f, 1, 1, 2)
	c := claims(f, allScopes)
	tok, err := k.Sign(c)
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		"", ".", "...", "v1...", "v1.a.1.b", tok, tok + ".", tok[:len(tok)/2], strings.ToUpper(tok),
		strings.Replace(tok, ".1.", ".2.", 1), "v1.e30.1.AAAA", strings.Repeat("v1.", 500),
		"\x00\xff", tok + "\x00",
	} {
		f.Add(s, uint8(ScopeKey), c.AssetID)
	}
	f.Fuzz(func(t *testing.T, tk string, need uint8, asset string) {
		got, err := k.Verify(tk, t0, Scope(need), asset)
		if err != nil {
			if !isInvalid(err) || got != (Claims{}) {
				t.Fatalf("failure must be ErrInvalid with zero claims: %v", err)
			}
			return
		}
		if !got.Scopes.Has(Scope(need)) || got.AssetID != asset {
			t.Fatal("accepted a token that does not satisfy the request")
		}
	})
}

func TestOpenReturnsClaimsWithoutAnAssetCheck(t *testing.T) {
	k := testKeyring(t, 1, 1)
	c := claims(t, ScopeManifest|ScopeSegment)
	tok, err := k.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Open(tok, t0.Add(time.Minute), ScopeSegment)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != c.SessionID || got.AssetID != c.AssetID || got.TenantID != c.TenantID || got.Scopes != c.Scopes {
		t.Fatalf("claims = %+v, want %+v", got, c)
	}
	for name, run := range map[string]func() error{
		"scope":   func() error { _, err := k.Open(tok, t0, ScopeKey); return err },
		"expired": func() error { _, err := k.Open(tok, t0.Add(time.Hour), ScopeSegment); return err },
		"no need": func() error { _, err := k.Open(tok, t0, 0); return err },
		"garbage": func() error { _, err := k.Open("garbage", t0, ScopeSegment); return err },
	} {
		if err := run(); !isInvalid(err) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestSignRequiresATenant(t *testing.T) {
	k := testKeyring(t, 1, 1)
	c := claims(t, ScopeManifest)
	c.TenantID = ""
	if _, err := k.Sign(c); err == nil {
		t.Fatal("Sign accepted claims without a tenant")
	}
}
