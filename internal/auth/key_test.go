package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestNewKeyShape(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		k, err := NewKey()
		if err != nil {
			t.Fatal(err)
		}
		full := k.Reveal()
		if len(full) != KeyLen || KeyLen != 59 {
			t.Fatalf("length %d, want 59", len(full))
		}
		if !strings.HasPrefix(full, "cf_") || full[15] != '_' {
			t.Fatalf("unexpected shape %q", k)
		}
		for _, c := range k.Prefix() {
			if !strings.ContainsRune(prefixAlphabet, c) {
				t.Fatalf("prefix char %q outside the Crockford alphabet", c)
			}
		}
		if seen[full] {
			t.Fatal("duplicate key generated")
		}
		seen[full] = true
	}
}

func TestParseKeyRoundTrip(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseKey(k.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	if got.Prefix() != k.Prefix() || got.Reveal() != k.Reveal() {
		t.Fatal("round trip changed the key")
	}
}

func TestParseKeyRejects(t *testing.T) {
	k, _ := NewKey()
	good := k.Reveal()
	secret := good[16:]
	// A secret whose last character carries non-zero trailing bits is not canonical.
	nonCanonical := good[:len(good)-1] + "B"
	if good[len(good)-1] == 'B' {
		nonCanonical = good[:len(good)-1] + "C"
	}
	bad := map[string]string{
		"empty":             "",
		"no tag":            "xx_" + good[3:],
		"uppercase tag":     "CF_" + good[3:],
		"short prefix":      "cf_" + good[3:14] + "_" + secret,
		"long prefix":       "cf_" + good[3:15] + "0_" + secret,
		"uppercase prefix":  "cf_" + strings.ToUpper(good[3:15]) + "_" + secret,
		"excluded letter i": "cf_" + "i" + good[4:15] + "_" + secret,
		"excluded letter l": "cf_" + "l" + good[4:15] + "_" + secret,
		"excluded letter o": "cf_" + "o" + good[4:15] + "_" + secret,
		"excluded letter u": "cf_" + "u" + good[4:15] + "_" + secret,
		"wrong separator":   good[:15] + "-" + secret,
		"short secret":      good[:len(good)-1],
		"long secret":       good + "A",
		"padded secret":     good[:len(good)-1] + "=",
		"standard base64":   good[:16] + strings.ReplaceAll(strings.ReplaceAll(secret, "-", "+"), "_", "/") + "",
		"leading space":     " " + good,
		"trailing space":    good + " ",
		"trailing newline":  good + "\n",
		"embedded newline":  good[:20] + "\n" + good[21:],
		"non canonical":     nonCanonical,
		"nul byte":          good[:20] + "\x00" + good[21:],
		"unicode":           good[:20] + "é" + good[22:],
	}
	for name, in := range bad {
		if strings.Contains(secret, "-") || strings.Contains(secret, "_") || name != "standard base64" {
			if _, err := ParseKey(in); err == nil {
				t.Errorf("%s: ParseKey accepted %q", name, in)
			} else if !errors.Is(err, ErrKeyFormat) || strings.Contains(err.Error(), in) && in != "" {
				t.Errorf("%s: unexpected error %v", name, err)
			}
		}
	}
}

func TestParseKeyAcceptsUnderscoreAndDashInSecret(t *testing.T) {
	// The secret alphabet contains '_' and '-': parsing is by position, not by splitting.
	for range 2000 {
		k, _ := NewKey()
		got, err := ParseKey(k.Reveal())
		if err != nil || got.Reveal() != k.Reveal() {
			t.Fatalf("valid key rejected: %v", err)
		}
	}
}

func TestHashIsHMACSHA256OverSecretBytes(t *testing.T) {
	k, _ := NewKey()
	pepper := bytes.Repeat([]byte{7}, 32)
	m := hmac.New(sha256.New, pepper)
	raw, _ := base64.RawURLEncoding.DecodeString(k.Reveal()[16:])
	m.Write(raw)
	if !bytes.Equal(k.Hash(pepper), m.Sum(nil)) {
		t.Fatal("hash is not HMAC-SHA256(pepper, secret)")
	}
	other := bytes.Repeat([]byte{8}, 32)
	if bytes.Equal(k.Hash(pepper), k.Hash(other)) {
		t.Fatal("different peppers gave the same hash")
	}
	k2, _ := NewKey()
	if bytes.Equal(k.Hash(pepper), k2.Hash(pepper)) {
		t.Fatal("different secrets gave the same hash")
	}
}

func TestWithNewSecretKeepsPrefix(t *testing.T) {
	k, _ := NewKey()
	k2, err := WithNewSecret(k.Prefix())
	if err != nil {
		t.Fatal(err)
	}
	if k2.Prefix() != k.Prefix() || k2.Reveal() == k.Reveal() {
		t.Fatal("rotation must keep the prefix and change the secret")
	}
	if _, err := WithNewSecret("short"); err == nil {
		t.Fatal("invalid prefix accepted")
	}
}

func TestKeyNeverPrintsItsSecret(t *testing.T) {
	k, _ := NewKey()
	secret := k.Reveal()[16:]
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("x", "key", k, slog.Any("k2", k))
	js, _ := json.Marshal(struct{ K Key }{k})
	for name, out := range map[string]string{
		"%v":   fmt.Sprintf("%v", k),
		"%+v":  fmt.Sprintf("%+v", k),
		"%#v":  fmt.Sprintf("%#v", k),
		"%s":   fmt.Sprintf("%s", k), //nolint:gosimple // exercising the verb
		"%x":   fmt.Sprintf("%x", k),
		"ptr":  fmt.Sprintf("%v", &k),
		"slog": logBuf.String(),
		"json": string(js),
		"err":  fmt.Errorf("wrapped: %v", k).Error(),
	} {
		if strings.Contains(out, secret) || strings.Contains(out, k.Reveal()) {
			t.Errorf("%s leaks the secret: %s", name, out)
		}
		if !strings.Contains(out, "[redacted]") {
			t.Errorf("%s does not show the redaction marker: %s", name, out)
		}
	}
}

func FuzzParseKey(f *testing.F) {
	k, _ := NewKey()
	f.Add(k.Reveal())
	f.Add("")
	f.Add("cf_")
	f.Add("cf_000000000000_" + strings.Repeat("A", 43))
	f.Add("cf_000000000000_" + strings.Repeat("_", 43))
	f.Add(k.Reveal() + "\n")
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseKey(s)
		if err != nil {
			if !errors.Is(err, ErrKeyFormat) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		// Anything accepted is canonical: it re-renders to exactly the input.
		if got.Reveal() != s {
			t.Fatalf("accepted a non-canonical key")
		}
		if len(s) != KeyLen {
			t.Fatalf("accepted length %d", len(s))
		}
	})
}
