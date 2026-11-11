package viewerauth_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth/viewerauthtest"
)

func TestParseUploadedJWKAccepts(t *testing.T) {
	for _, alg := range []string{"EdDSA", "ES256", "RS256"} {
		k := viewerauthtest.NewKey(t, alg, "k1")
		pk, err := viewerauth.ParseUploadedJWK("k1", k.PublicJWK(t))
		if err != nil || pk.Alg != alg || pk.Kid != "k1" {
			t.Fatalf("%s: %+v, %v", alg, pk, err)
		}
		// The stored form is the canonical public JWK and parses back to the same key.
		back, err := viewerauth.ParseStoredJWK("k1", alg, pk.JWK)
		if err != nil || back.Alg != alg {
			t.Fatalf("%s stored form: %v", alg, err)
		}
		var m map[string]any
		if err := json.Unmarshal(pk.JWK, &m); err != nil || m["d"] != nil || m["use"] != "sig" {
			t.Fatalf("%s canonical form: %v %v", alg, m, err)
		}
	}
}

func TestParseUploadedJWKRejects(t *testing.T) {
	ed := viewerauthtest.NewKey(t, "EdDSA", "k")
	es := viewerauthtest.NewKey(t, "ES256", "k")
	rs := viewerauthtest.NewKey(t, "RS256", "k")
	short := viewerauthtest.RSAKeyBits(t, "k", 1024)

	withAlg := func(jwk []byte, alg string) []byte {
		var m map[string]any
		if err := json.Unmarshal(jwk, &m); err != nil {
			t.Fatal(err)
		}
		m["alg"] = alg
		b, _ := json.Marshal(m)
		return b
	}
	without := func(jwk []byte, name string) []byte {
		var m map[string]any
		if err := json.Unmarshal(jwk, &m); err != nil {
			t.Fatal(err)
		}
		delete(m, name)
		b, _ := json.Marshal(m)
		return b
	}
	set := func(jwk []byte, name string, v any) []byte {
		var m map[string]any
		if err := json.Unmarshal(jwk, &m); err != nil {
			t.Fatal(err)
		}
		m[name] = v
		b, _ := json.Marshal(m)
		return b
	}
	p384 := `{"kty":"EC","crv":"P-384","alg":"ES256","x":"iA7lWQXGsAv0n4hnDzxfLWo4mL6cG8x6LkbB0Q9m6l6TfN2sH0u6kqC9wU3t7QcL","y":"u3t7QcLiA7lWQXGsAv0n4hnDzxfLWo4mL6cG8x6LkbB0Q9m6l6TfN2sH0u6kqC9w"}`

	cases := map[string][]byte{
		"private ed25519":              ed.PrivateJWK(t),
		"private ec":                   es.PrivateJWK(t),
		"private rsa":                  rs.PrivateJWK(t),
		"public rsa with a d member":   set(rs.PublicJWK(t), "d", "AQAB"),
		"rsa 1024 bits":                short.PublicJWK(t),
		"alg does not match key (ed)":  withAlg(ed.PublicJWK(t), "RS256"),
		"alg does not match key (ec)":  withAlg(es.PublicJWK(t), "EdDSA"),
		"alg does not match key (rsa)": withAlg(rs.PublicJWK(t), "ES256"),
		"alg HS256":                    withAlg(rs.PublicJWK(t), "HS256"),
		"alg none":                     withAlg(rs.PublicJWK(t), "none"),
		"alg PS256 (not allowed)":      withAlg(rs.PublicJWK(t), "PS256"),
		"missing alg":                  without(ed.PublicJWK(t), "alg"),
		"use enc":                      set(ed.PublicJWK(t), "use", "enc"),
		"kid mismatch":                 set(ed.PublicJWK(t), "kid", "other"),
		"unknown kty":                  []byte(`{"kty":"XYZ","alg":"EdDSA","x":"AAAA"}`),
		"symmetric key":                []byte(`{"kty":"oct","alg":"RS256","k":"c2VjcmV0"}`),
		"curve P-384":                  []byte(p384),
		"unknown OKP curve":            []byte(`{"kty":"OKP","crv":"Ed448","alg":"EdDSA","x":"AAAA"}`),
		"x25519 (key agreement)":       []byte(`{"kty":"OKP","crv":"X25519","alg":"EdDSA","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}`),
		"not json":                     []byte(`nope`),
		"empty object":                 []byte(`{}`),
	}
	for name, raw := range cases {
		_, err := viewerauth.ParseUploadedJWK("k", raw)
		var ke *viewerauth.ErrKey
		if !errors.As(err, &ke) {
			t.Errorf("%s: accepted or wrong error: %v", name, err)
			continue
		}
		// The message never quotes the key.
		if strings.Contains(ke.Msg, "AQAB") || strings.Contains(ke.Msg, "c2VjcmV0") {
			t.Errorf("%s: the error quotes the key: %q", name, ke.Msg)
		}
	}
}

func TestParseJWKSSkipsUnusableKeys(t *testing.T) {
	good := viewerauthtest.NewKey(t, "EdDSA", "good")
	goodRSA := viewerauthtest.NewKey(t, "RS256", "rsa")
	short := viewerauthtest.RSAKeyBits(t, "short", 1024)
	priv := viewerauthtest.NewKey(t, "ES256", "priv")
	dupA := viewerauthtest.NewKey(t, "EdDSA", "dup")
	dupB := viewerauthtest.NewKey(t, "EdDSA", "dup")
	noKid := viewerauthtest.NewKey(t, "EdDSA", "")

	doc := `{"keys":[` + strings.Join([]string{
		string(good.PublicJWK(t)), string(goodRSA.PublicJWK(t)), string(short.PublicJWK(t)), string(priv.PrivateJWK(t)),
		string(dupA.PublicJWK(t)), string(dupB.PublicJWK(t)), string(noKid.PublicJWK(t)),
		`{"kty":"XYZ","kid":"weird"}`, `{"kty":"oct","kid":"hmac","k":"c2VjcmV0"}`,
	}, ",") + `]}`
	keys, err := viewerauth.ParseJWKS([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys["good"].Alg != "EdDSA" || keys["rsa"].Alg != "RS256" {
		t.Fatalf("keys = %v", keys)
	}
	for _, bad := range []string{`{}`, `{"keys":[]}`, `not json`, `{"keys":[{"kty":"oct","kid":"a","k":"AA"}]}`} {
		if _, err := viewerauth.ParseJWKS([]byte(bad)); err == nil {
			t.Errorf("ParseJWKS(%q) succeeded", bad)
		}
	}
}
