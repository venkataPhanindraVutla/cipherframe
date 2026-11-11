//go:build integration

package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func keyItems(t *testing.T, r resp) []map[string]any {
	t.Helper()
	raw, ok := r.m["items"].([]any)
	if !ok {
		t.Fatalf("no items in %s", r.raw)
	}
	out := make([]map[string]any, len(raw))
	for i, v := range raw {
		out[i] = v.(map[string]any)
	}
	return out
}

func TestSigningKeysAdminLifecycle(t *testing.T) {
	h := newHarness(t)
	admin, res := h.bootstrap("acme")
	ctx := context.Background()
	if err := h.signing.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}

	list := h.mustOK(h.do(admin, "GET", "/v1/signing-keys", nil), 200)
	items := keyItems(t, list)
	if len(items) != 1 || items[0]["current"] != true || items[0]["state"] != "active" || items[0]["algorithm"] != "ed25519" || items[0]["retired_at"] != nil {
		t.Fatalf("list = %s", list.raw)
	}
	firstID := items[0]["key_id"].(string)
	if !strings.HasPrefix(firstID, "sk_") {
		t.Fatalf("key id %q", firstID)
	}
	if pk, err := base64.StdEncoding.DecodeString(items[0]["public_key"].(string)); err != nil || len(pk) != ed25519.PublicKeySize {
		t.Fatalf("public key %v %v", pk, err)
	}

	// Rotation: 201, new current key, the old one stays active.
	rot := h.mustOK(h.do(admin, "POST", "/v1/signing-keys/rotate", nil), 201)
	if rot.m["current"] != true || rot.m["state"] != "active" || rot.m["key_id"] == firstID {
		t.Fatalf("rotate = %s", rot.raw)
	}
	items = keyItems(t, h.mustOK(h.do(admin, "GET", "/v1/signing-keys", nil), 200))
	if len(items) != 2 || items[0]["key_id"] != firstID || items[0]["current"] != false || items[0]["state"] != "active" || items[1]["current"] != true {
		t.Fatalf("after rotate = %v", items)
	}

	// The current key cannot be retired.
	h.wantStatus(h.do(admin, "POST", "/v1/signing-keys/"+rot.m["key_id"].(string)+"/retire", nil), 409, "conflict")
	// The old one can; it stays listed as retired.
	ret := h.mustOK(h.do(admin, "POST", "/v1/signing-keys/"+firstID+"/retire", nil), 200)
	if ret.m["state"] != "retired" || ret.m["retired_at"] == nil || ret.m["current"] != false {
		t.Fatalf("retire = %s", ret.raw)
	}
	h.wantStatus(h.do(admin, "POST", "/v1/signing-keys/sk_00000000000000000000000001/retire", nil), 404, "not_found")
	h.wantStatus(h.do(admin, "POST", "/v1/signing-keys/nope/retire", nil), 404, "not_found")
	items = keyItems(t, h.mustOK(h.do(admin, "GET", "/v1/signing-keys", nil), 200))
	if len(items) != 2 || items[0]["state"] != "retired" {
		t.Fatalf("after retire = %v", items)
	}

	// Audit events carry the actor and the key id, never a secret.
	rows, err := h.pool.Query(ctx, "SELECT action, target, client_id FROM audit_events WHERE tenant_id = $1 AND action LIKE 'signing_key.%' ORDER BY created_at, id", res.Tenant.ID.UUID())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var action, target string
		var client [16]byte
		if err := rows.Scan(&action, &target, &client); err != nil {
			t.Fatal(err)
		}
		if client != [16]byte(res.Client.ID.UUID()) {
			t.Fatalf("audit client = %x", client)
		}
		got = append(got, action+" "+target)
	}
	want := []string{"signing_key.rotate " + rot.m["key_id"].(string), "signing_key.retire " + firstID}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("audit = %v, want %v", got, want)
	}
}

func TestSigningKeysRequireAdmin(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	cli := h.newClient(admin, "svc")
	rk := str(h.newKey(admin, cli, "reader", []string{"assets:read", "assets:write"}).m, "key")
	if err := h.signing.EnsureCurrent(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/signing-keys"},
		{"POST", "/v1/signing-keys/rotate"},
		{"POST", "/v1/signing-keys/sk_00000000000000000000000001/retire"},
	} {
		h.wantStatus(h.do(rk, c.method, c.path, nil), 403, "forbidden")
		h.wantStatus(h.do("", c.method, c.path, nil), 401, "unauthenticated")
	}
	// Nothing changed.
	if n := len(keyItems(t, h.mustOK(h.do(admin, "GET", "/v1/signing-keys", nil), 200))); n != 1 {
		t.Fatalf("keys = %d, want 1", n)
	}
}

func TestSigningKeyRotationWhenKMSIsDown(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	ctx := context.Background()
	if err := h.signing.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	h.kms.SetOutage(true)
	r := h.do(admin, "POST", "/v1/signing-keys/rotate", nil)
	h.wantStatus(r, 503, "dependency_unavailable")
	h.kms.SetOutage(false)
	if n := len(keyItems(t, h.mustOK(h.do(admin, "GET", "/v1/signing-keys", nil), 200))); n != 1 {
		t.Fatalf("keys = %d after a failed rotation, want 1", n)
	}
	// Listing needs no key service.
	h.kms.SetOutage(true)
	h.mustOK(h.do(admin, "GET", "/v1/signing-keys", nil), 200)
}

func TestWellKnownKeySetOnAPI(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	if err := h.signing.EnsureCurrent(context.Background()); err != nil {
		t.Fatal(err)
	}
	// No credentials needed.
	r := h.mustOK(h.do("", "GET", "/.well-known/cipherframe-keys.json", nil), 200)
	if got := r.hdr.Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := r.hdr.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("CORS = %q", got)
	}
	if got := r.hdr.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type = %q", got)
	}
	keys := r.m["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("keys = %s", r.raw)
	}
	k := keys[0].(map[string]any)
	for _, f := range []string{"keyid", "alg", "public_key", "status", "created_at"} {
		if _, ok := k[f]; !ok {
			t.Fatalf("key without %q: %s", f, r.raw)
		}
	}
	if _, has := k["retired_at"]; has || k["alg"] != "ed25519" || k["status"] != "active" {
		t.Fatalf("key = %v", k)
	}
	// No tenant, secret or envelope field ever appears.
	for _, banned := range []string{"private", "envelope", "seed", "tenant", "current"} {
		if bytes.Contains(r.raw, []byte(banned)) {
			t.Fatalf("the key set contains %q: %s", banned, r.raw)
		}
	}
	_ = admin
}

func TestSigningKeysNoPrivateMaterialInLogs(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	ctx := context.Background()
	if err := h.signing.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	h.mustOK(h.do(admin, "POST", "/v1/signing-keys/rotate", nil), 201)
	if _, _, err := h.signing.Sign(ctx, []byte("m")); err != nil {
		t.Fatal(err)
	}
	var env []byte
	if err := h.pool.QueryRow(ctx, "SELECT private_envelope FROM signing_keys WHERE is_current").Scan(&env); err != nil {
		t.Fatal(err)
	}
	logs := h.logs.String()
	for _, c := range [][]byte{env, []byte(base64.StdEncoding.EncodeToString(env)), []byte(base64.RawURLEncoding.EncodeToString(env))} {
		if strings.Contains(logs, string(c)) {
			t.Fatal("the logs contain a wrapped signing key")
		}
	}
	for _, banned := range []string{"private_envelope", "seed"} {
		if strings.Contains(logs, banned) {
			t.Fatalf("the logs mention %q", banned)
		}
	}
}
