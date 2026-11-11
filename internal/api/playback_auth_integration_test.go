//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth/viewerauthtest"
)

func authBody(edit func(map[string]any)) map[string]any {
	b := map[string]any{
		"jwt_enabled": true, "jwt_issuer": "https://issuer.example.com", "jwt_audiences": []any{"cipherframe"},
		"jwt_jwks_url": "https://issuer.example.com/.well-known/jwks.json", "jwt_viewer_claim": "sub",
		"callback_enabled": false, "callback_url": "https://app.example.com/cipherframe/authorize",
	}
	if edit != nil {
		edit(b)
	}
	return b
}

func jwkBody(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPlaybackAuthDefaultsAndRoundTrip(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	otherKey, _ := h.bootstrap("other")

	r := h.mustOK(h.do(key, "GET", "/v1/playback-auth", nil), 200)
	want := map[string]any{
		"jwt_enabled": false, "jwt_issuer": "", "jwt_audiences": []any{}, "jwt_jwks_url": nil, "jwt_viewer_claim": "sub",
		"jwt_keys": []any{}, "callback_enabled": false, "callback_url": nil,
		"callback_secret_configured": false, "callback_secret_version": 0.0,
	}
	if !reflect.DeepEqual(r.m, want) {
		t.Fatalf("defaults = %s", r.raw)
	}

	// jwt_enabled needs a JWKS URL (here) or an uploaded key.
	put := h.mustOK(h.do(key, "PUT", "/v1/playback-auth", authBody(nil)), 200)
	if _, ok := put.m["updated_at"].(string); !ok || put.m["jwt_jwks_url"] != "https://issuer.example.com/.well-known/jwks.json" {
		t.Fatalf("put = %s", put.raw)
	}
	got := h.mustOK(h.do(key, "GET", "/v1/playback-auth", nil), 200)
	if !reflect.DeepEqual(got.m, put.m) {
		t.Fatalf("GET %s != PUT %s", got.raw, put.raw)
	}
	// A full replacement: fields left out go back to their defaults.
	r = h.mustOK(h.do(key, "PUT", "/v1/playback-auth", map[string]any{"jwt_enabled": false, "callback_enabled": false}), 200)
	if r.m["jwt_issuer"] != "" || r.m["jwt_jwks_url"] != nil || r.m["jwt_viewer_claim"] != "sub" || !reflect.DeepEqual(r.m["jwt_audiences"], []any{}) {
		t.Fatalf("replacement = %s", r.raw)
	}
	// Another tenant is unaffected.
	other := h.mustOK(h.do(otherKey, "GET", "/v1/playback-auth", nil), 200)
	if other.m["jwt_enabled"] != false {
		t.Fatalf("another tenant = %s", other.raw)
	}
	var n int
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'playback_auth.update' AND client_id = $2",
		res.Tenant.ID.UUID(), res.Client.ID.UUID()).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit events = %d, %v; want 2", n, err)
	}
}

func TestPlaybackAuthValidation(t *testing.T) {
	h := newHarness(t)
	key, _ := h.bootstrap("acme")
	with := func(k string, v any) map[string]any { return authBody(func(b map[string]any) { b[k] = v }) }
	cases := map[string]struct {
		body  map[string]any
		field string
	}{
		"http jwks url":             {with("jwt_jwks_url", "http://issuer.example.com/jwks"), "jwt_jwks_url"},
		"jwks url with credentials": {with("jwt_jwks_url", "https://u:p@issuer.example.com/jwks"), "jwt_jwks_url"},
		"jwks url on loopback":      {with("jwt_jwks_url", "https://127.0.0.1/jwks"), "jwt_jwks_url"},
		"jwks url on metadata":      {with("jwt_jwks_url", "https://169.254.169.254/latest"), "jwt_jwks_url"},
		"jwks url on a private ip":  {with("jwt_jwks_url", "https://10.0.0.5/jwks"), "jwt_jwks_url"},
		"jwks url on ipv6 loopback": {with("jwt_jwks_url", "https://[::1]/jwks"), "jwt_jwks_url"},
		"callback url is http":      {with("callback_url", "http://app.example.com/cb"), "callback_url"},
		"callback url private":      {with("callback_url", "https://192.168.1.10/cb"), "callback_url"},
		"enabled without issuer":    {with("jwt_issuer", ""), "jwt_issuer"},
		"enabled without audiences": {with("jwt_audiences", []any{}), "jwt_audiences"},
		"duplicate audience":        {with("jwt_audiences", []any{"a", "a"}), "jwt_audiences[1]"},
		"empty audience":            {with("jwt_audiences", []any{""}), "jwt_audiences[0]"},
		"too many audiences":        {with("jwt_audiences", []any{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}), "jwt_audiences"},
		"viewer claim with space":   {with("jwt_viewer_claim", "a b"), "jwt_viewer_claim"},
		"callback without url":      {with("callback_url", nil), ""}, // fine while callbacks are off
	}
	for name, c := range cases {
		r := h.do(key, "PUT", "/v1/playback-auth", c.body)
		if c.field == "" {
			if r.status != 200 {
				t.Errorf("%s: status %d: %s", name, r.status, r.raw)
			}
			continue
		}
		if r.status != 400 || r.code() != "invalid_request" || !strings.Contains(strings.Join(fieldErrors(r), ","), c.field) {
			t.Errorf("%s: status %d fields %v: %s", name, r.status, fieldErrors(r), r.raw)
		}
		// Messages never quote the submitted value.
		if strings.Contains(string(r.raw), "169.254") || strings.Contains(string(r.raw), "u:p@") {
			t.Errorf("%s: the error quotes the value: %s", name, r.raw)
		}
	}
	// The failed PUTs stored nothing.
	got := h.mustOK(h.do(key, "GET", "/v1/playback-auth", nil), 200)
	if got.m["jwt_jwks_url"] != nil && !strings.HasPrefix(got.m["jwt_jwks_url"].(string), "https://issuer.example.com") {
		t.Fatalf("a rejected PUT changed the settings: %s", got.raw)
	}

	// Enabling callbacks needs a secret first.
	r := h.do(key, "PUT", "/v1/playback-auth", with("callback_enabled", true))
	if r.status != 400 || !strings.Contains(strings.Join(fieldErrors(r), ","), "callback_enabled") {
		t.Fatalf("callback without a secret: %d %s", r.status, r.raw)
	}
	h.mustOK(h.do(key, "POST", "/v1/playback-auth/callback-secret/rotate", nil), 200)
	h.mustOK(h.do(key, "PUT", "/v1/playback-auth", with("callback_enabled", true)), 200)

	// Enabling JWT needs a key source: a JWKS URL or an uploaded key.
	noSource := authBody(func(b map[string]any) { b["jwt_jwks_url"] = nil })
	r = h.do(key, "PUT", "/v1/playback-auth", noSource)
	if r.status != 400 || !strings.Contains(strings.Join(fieldErrors(r), ","), "jwt_enabled") {
		t.Fatalf("jwt without a key source: %d %s", r.status, r.raw)
	}
	ed := viewerauthtest.NewKey(t, "EdDSA", "k1")
	h.mustOK(h.do(key, "PUT", "/v1/playback-auth/jwt-keys/k1", jwkBody(t, ed.PublicJWK(t))), 200)
	h.mustOK(h.do(key, "PUT", "/v1/playback-auth", noSource), 200)
	// Unknown fields and a missing body.
	h.wantStatus(h.do(key, "PUT", "/v1/playback-auth", map[string]any{"jwt_enabled": false}), 400, "invalid_request")
}

func TestPlaybackAuthJWTKeys(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	otherKey, _ := h.bootstrap("other")

	// The three accepted algorithms.
	for _, alg := range []string{"EdDSA", "ES256", "RS256"} {
		k := viewerauthtest.NewKey(t, alg, "key-"+alg)
		r := h.mustOK(h.do(key, "PUT", "/v1/playback-auth/jwt-keys/key-"+alg, jwkBody(t, k.PublicJWK(t))), 200)
		if r.m["kid"] != "key-"+alg || r.m["alg"] != alg {
			t.Fatalf("%s: %s", alg, r.raw)
		}
	}
	got := h.mustOK(h.do(key, "GET", "/v1/playback-auth", nil), 200)
	if keys, _ := got.m["jwt_keys"].([]any); len(keys) != 3 {
		t.Fatalf("keys = %s", got.raw)
	}
	// The stored form is the public JWK only.
	var stored string
	if err := h.pool.QueryRow(context.Background(), "SELECT jwk::text FROM playback_jwt_keys WHERE tenant_id = $1 AND kid = 'key-EdDSA'", res.Tenant.ID.UUID()).Scan(&stored); err != nil ||
		strings.Contains(stored, `"d"`) || !strings.Contains(stored, `"use": "sig"`) {
		t.Fatalf("stored = %s, %v", stored, err)
	}

	// Refusals.
	ed := viewerauthtest.NewKey(t, "EdDSA", "bad")
	es := viewerauthtest.NewKey(t, "ES256", "bad")
	rs := viewerauthtest.NewKey(t, "RS256", "bad")
	short := viewerauthtest.RSAKeyBits(t, "bad", 1024)
	mod := func(raw []byte, k string, v any) map[string]any {
		m := jwkBody(t, raw)
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	bad := map[string]map[string]any{
		"private ed25519":    jwkBody(t, ed.PrivateJWK(t)),
		"private ec":         jwkBody(t, es.PrivateJWK(t)),
		"private rsa":        jwkBody(t, rs.PrivateJWK(t)),
		"public with d":      mod(rs.PublicJWK(t), "d", "AQAB"),
		"rsa 1024":           jwkBody(t, short.PublicJWK(t)),
		"alg HS256":          mod(rs.PublicJWK(t), "alg", "HS256"),
		"alg none":           mod(rs.PublicJWK(t), "alg", "none"),
		"alg mismatch":       mod(ed.PublicJWK(t), "alg", "RS256"),
		"missing alg":        mod(ed.PublicJWK(t), "alg", ""),
		"unknown kty":        {"kty": "XYZ", "alg": "EdDSA"},
		"symmetric":          {"kty": "oct", "alg": "RS256", "k": "c2VjcmV0"},
		"unknown curve":      {"kty": "EC", "crv": "secp256k1", "alg": "ES256", "x": "AAAA", "y": "AAAA"},
		"use enc":            mod(ed.PublicJWK(t), "use", "enc"),
		"kid differs":        mod(ed.PublicJWK(t), "kid", "other"),
		"kid not in the url": mod(ed.PublicJWK(t), "kid", "bad"), // the path kid below is "bad kid"
	}
	for name, body := range bad {
		path := "/v1/playback-auth/jwt-keys/bad"
		if name == "kid not in the url" {
			path = "/v1/playback-auth/jwt-keys/other-kid"
		}
		r := h.do(key, "PUT", path, body)
		if r.status != 400 || r.code() != "invalid_request" {
			t.Errorf("%s: status %d: %s", name, r.status, r.raw)
			continue
		}
		for _, secret := range []string{"c2VjcmV0", "AQAB"} {
			if strings.Contains(string(r.raw), secret) {
				t.Errorf("%s: the error quotes the key", name)
			}
		}
	}
	// A bad kid in the path.
	h.wantStatus(h.do(key, "PUT", "/v1/playback-auth/jwt-keys/"+strings.Repeat("k", 129), jwkBody(t, ed.PublicJWK(t))), 400, "invalid_request")
	var n int
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM playback_jwt_keys WHERE tenant_id = $1", res.Tenant.ID.UUID()).Scan(&n); err != nil || n != 3 {
		t.Fatalf("keys after the refusals = %d, %v", n, err)
	}

	// Replace a key; the cap is 20 per tenant, and per tenant only.
	h.mustOK(h.do(key, "PUT", "/v1/playback-auth/jwt-keys/key-EdDSA", jwkBody(t, viewerauthtest.NewKey(t, "EdDSA", "key-EdDSA").PublicJWK(t))), 200)
	for i := 3; i < 20; i++ {
		k := viewerauthtest.NewKey(t, "EdDSA", fmt.Sprintf("extra-%d", i))
		h.mustOK(h.do(key, "PUT", "/v1/playback-auth/jwt-keys/"+k.Kid, jwkBody(t, k.PublicJWK(t))), 200)
	}
	over := viewerauthtest.NewKey(t, "EdDSA", "over")
	h.wantStatus(h.do(key, "PUT", "/v1/playback-auth/jwt-keys/over", jwkBody(t, over.PublicJWK(t))), 409, "conflict")
	h.mustOK(h.do(otherKey, "PUT", "/v1/playback-auth/jwt-keys/over", jwkBody(t, over.PublicJWK(t))), 200)

	// Delete: once, then not found; another tenant's kid is not found either.
	h.mustOK(h.do(key, "DELETE", "/v1/playback-auth/jwt-keys/key-ES256", nil), 204)
	h.wantStatus(h.do(key, "DELETE", "/v1/playback-auth/jwt-keys/key-ES256", nil), 404, "not_found")
	h.wantStatus(h.do(key, "DELETE", "/v1/playback-auth/jwt-keys/over", nil), 404, "not_found")
	h.mustOK(h.do(key, "PUT", "/v1/playback-auth/jwt-keys/over", jwkBody(t, over.PublicJWK(t))), 200)

	// Audited: kid only, never the key.
	var actions []string
	rows, err := h.pool.Query(context.Background(), "SELECT action || ' ' || coalesce(target, '') FROM audit_events WHERE tenant_id = $1 AND action LIKE 'playback_auth.jwt_key.%' ORDER BY created_at", res.Tenant.ID.UUID())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, a)
	}
	if len(actions) != 3+1+17+1+1 || actions[0] != "playback_auth.jwt_key.put key-EdDSA" || !strings.HasPrefix(actions[len(actions)-2], "playback_auth.jwt_key.delete key-ES256") {
		t.Fatalf("audit trail = %v", actions)
	}
}

func TestPlaybackAuthCallbackSecretRotation(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	ctx := context.Background()

	r1 := h.mustOK(h.do(key, "POST", "/v1/playback-auth/callback-secret/rotate", nil), 200)
	secret1 := str(r1.m, "secret")
	if !strings.HasPrefix(secret1, "whsec_") || len(secret1) != len("whsec_")+44 || r1.m["version"] != 1.0 || r1.hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("first rotation = %s (cache-control %q)", r1.raw, r1.hdr.Get("Cache-Control"))
	}
	if _, ok := r1.m["previous_valid_until"]; ok {
		t.Fatal("the first rotation has no previous secret")
	}
	h.keys = append(h.keys, secret1)

	// The secret is shown once: GET shows its state, never its value, nor does the database.
	get := h.mustOK(h.do(key, "GET", "/v1/playback-auth", nil), 200)
	if get.m["callback_secret_configured"] != true || get.m["callback_secret_version"] != 1.0 || strings.Contains(string(get.raw), secret1[6:]) {
		t.Fatalf("GET after the rotation = %s", get.raw)
	}
	var dump string
	if err := h.pool.QueryRow(ctx, "SELECT playback_auth::text FROM playback_auth WHERE tenant_id = $1", res.Tenant.ID.UUID()).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	raw := secret1[6:]
	if strings.Contains(dump, raw) {
		t.Fatal("the secret is stored in the clear")
	}

	// The second rotation keeps the first as the previous secret for 24 hours.
	r2 := h.mustOK(h.do(key, "POST", "/v1/playback-auth/callback-secret/rotate", nil), 200)
	secret2 := str(r2.m, "secret")
	h.keys = append(h.keys, secret2)
	until, err := time.Parse(time.RFC3339, str(r2.m, "previous_valid_until"))
	if secret2 == secret1 || r2.m["version"] != 2.0 || err != nil || time.Until(until) < 23*time.Hour || time.Until(until) > 25*time.Hour {
		t.Fatalf("second rotation = %s (%v)", r2.raw, err)
	}
	get = h.mustOK(h.do(key, "GET", "/v1/playback-auth", nil), 200)
	if _, ok := get.m["callback_previous_secret_valid_until"].(string); !ok || get.m["callback_secret_version"] != 2.0 {
		t.Fatalf("GET after the second rotation = %s", get.raw)
	}

	// A provider outage leaves the stored secret as it was and is a 503, not a half rotation.
	h.kms.SetOutage(true)
	h.wantStatus(h.do(key, "POST", "/v1/playback-auth/callback-secret/rotate", nil), 503, "dependency_unavailable")
	h.kms.SetOutage(false)
	get = h.mustOK(h.do(key, "GET", "/v1/playback-auth", nil), 200)
	if get.m["callback_secret_version"] != 2.0 {
		t.Fatalf("a failed rotation changed the version: %s", get.raw)
	}

	// Audited, with no secret.
	var n int
	if err := h.pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'playback_auth.callback_secret.rotate' AND client_id = $2",
		res.Tenant.ID.UUID(), res.Client.ID.UUID()).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit events = %d, %v; want 2", n, err)
	}
	if err := h.pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE target LIKE '%' || $1 || '%' OR request_id LIKE '%' || $1 || '%'", raw).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the secret reached the audit log: %d %v", n, err)
	}
	// And nothing reached the application log.
	logs := h.logs.String()
	for _, s := range []string{secret1, secret2, raw, secret2[6:]} {
		if strings.Contains(logs, s) {
			t.Fatal("a callback secret reached the log")
		}
	}
}

func TestPlaybackAuthNeedsTheAdminScope(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	cli := h.newClient(admin, "svc")
	k := h.newKey(admin, cli, "sessions only", []string{"sessions:write"})
	svc := str(k.m, "key")
	jwk := jwkBody(t, viewerauthtest.NewKey(t, "EdDSA", "k").PublicJWK(t))
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/v1/playback-auth", nil},
		{"PUT", "/v1/playback-auth", authBody(nil)},
		{"PUT", "/v1/playback-auth/jwt-keys/k", jwk},
		{"DELETE", "/v1/playback-auth/jwt-keys/k", nil},
		{"POST", "/v1/playback-auth/callback-secret/rotate", nil},
	} {
		h.wantStatus(h.do(svc, c.method, c.path, c.body), 403, "forbidden")
		h.wantStatus(h.do("", c.method, c.path, c.body), 401, "unauthenticated")
	}
}
