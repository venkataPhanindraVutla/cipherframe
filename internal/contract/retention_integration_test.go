//go:build integration

package contract

import (
	"context"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

// expiresAt reads the expires_at member of an asset response (zero when absent).
func expiresAt(t *testing.T, m map[string]any) time.Time {
	t.Helper()
	s, ok := m["expires_at"].(string)
	if !ok {
		return time.Time{}
	}
	at, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func near(t *testing.T, got, want time.Time) {
	t.Helper()
	if d := got.Sub(want); d < -time.Second || d > time.Second {
		t.Fatalf("expires_at = %v, want about %v", got, want)
	}
}

// Time-to-live: at creation (from the request, or from the tenant's default), changed and cleared
// with PATCH, validated, scoped and tenant-isolated. The default is no expiry.
func TestAssetRetentionSettings(t *testing.T) {
	e := newUpEnv(t)
	ctx := context.Background()
	other := e.newTenant("other")
	base := map[string]any{"size_bytes": 100, "upload_method": "multipart"}
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	asset := func(created map[string]any) map[string]any { return created["asset"].(map[string]any) }

	// No expiry unless asked for.
	m, _ := e.call(e.admin, "POST", "/v1/assets", base, 201)
	if !expiresAt(t, asset(m)).IsZero() || e.dbAsset(asset(m)["id"].(string)).ExpiresAt != nil {
		t.Fatalf("an asset without a time-to-live expires: %v", asset(m))
	}
	plainID := asset(m)["id"].(string)

	// ttl_seconds and expires_at at creation.
	m, _ = e.call(e.admin, "POST", "/v1/assets", with(map[string]any{"ttl_seconds": 7200}), 201)
	near(t, expiresAt(t, asset(m)), e.clk.Now().Add(2*time.Hour))
	if got := e.dbAsset(asset(m)["id"].(string)).ExpiresAt; got == nil {
		t.Fatal("the expiry was not stored")
	}
	abs := e.clk.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	m, _ = e.call(e.admin, "POST", "/v1/assets", with(map[string]any{"expires_at": abs.Format(time.RFC3339)}), 201)
	near(t, expiresAt(t, asset(m)), abs)
	for name, bad := range map[string]map[string]any{
		"both":          {"ttl_seconds": 3600, "expires_at": abs.Format(time.RFC3339)},
		"ttl too small": {"ttl_seconds": 59},
		"ttl too large": {"ttl_seconds": 315360001},
		"in the past":   {"expires_at": e.clk.Now().Add(-time.Hour).UTC().Format(time.RFC3339)},
		"too soon":      {"expires_at": e.clk.Now().Add(10 * time.Second).UTC().Format(time.RFC3339)},
		"ttl as string": {"ttl_seconds": "3600"},
	} {
		if _, ex := e.call(e.admin, "POST", "/v1/assets", with(bad), 400); ex.resp.StatusCode != 400 {
			t.Errorf("%s: status %d", name, ex.resp.StatusCode)
		}
	}

	// The tenant's default applies to assets created afterwards, and only to that tenant's.
	hour := 3600
	if _, err := e.repos.PutPrivacySettings(ctx, e.tenant.ID, db.PrivacySettings{AssetTTLSeconds: &hour}, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	m, _ = e.call(e.admin, "POST", "/v1/assets", base, 201)
	near(t, expiresAt(t, asset(m)), e.clk.Now().Add(time.Hour))
	m, _ = e.call(e.admin, "POST", "/v1/assets", with(map[string]any{"ttl_seconds": 600}), 201) // the request wins
	near(t, expiresAt(t, asset(m)), e.clk.Now().Add(10*time.Minute))
	m, _ = e.call(other, "POST", "/v1/assets", base, 201)
	if !expiresAt(t, asset(m)).IsZero() {
		t.Fatalf("another tenant's asset got this tenant's default: %v", asset(m))
	}
	// An asset that existed before the default keeps its (lack of) expiry.
	if m, _ = e.call(e.admin, "GET", "/v1/assets/"+plainID, nil, 200); !expiresAt(t, m).IsZero() {
		t.Fatalf("an existing asset changed with the tenant default: %v", m)
	}

	// PATCH: set from a time or a ttl, then clear with null either way.
	path := "/v1/assets/" + plainID
	m, _ = e.call(e.admin, "PATCH", path, map[string]any{"ttl_seconds": 1800}, 200)
	near(t, expiresAt(t, m), e.clk.Now().Add(30*time.Minute))
	m, _ = e.call(e.admin, "PATCH", path, map[string]any{"expires_at": abs.Format(time.RFC3339)}, 200)
	near(t, expiresAt(t, m), abs)
	m, _ = e.call(e.admin, "PATCH", path, map[string]any{"expires_at": nil}, 200)
	if !expiresAt(t, m).IsZero() || e.dbAsset(plainID).ExpiresAt != nil {
		t.Fatalf("null did not clear the expiry: %v", m)
	}
	e.call(e.admin, "PATCH", path, map[string]any{"ttl_seconds": 1800}, 200)
	m, _ = e.call(e.admin, "PATCH", path, map[string]any{"ttl_seconds": nil}, 200)
	if !expiresAt(t, m).IsZero() {
		t.Fatalf("a null ttl did not clear the expiry: %v", m)
	}
	for name, body := range map[string]any{
		"empty":         map[string]any{},
		"both":          map[string]any{"ttl_seconds": 600, "expires_at": abs.Format(time.RFC3339)},
		"unknown":       map[string]any{"keep": true},
		"ttl too small": map[string]any{"ttl_seconds": 5},
		"past":          map[string]any{"expires_at": e.clk.Now().Add(-time.Hour).UTC().Format(time.RFC3339)},
		"wrong type":    map[string]any{"expires_at": 12},
		"not a time":    map[string]any{"expires_at": "tomorrow"},
		"ttl float":     map[string]any{"ttl_seconds": 60.5},
	} {
		if _, ex := e.call(e.admin, "PATCH", path, body, 400); ex.resp.StatusCode != 400 {
			t.Errorf("%s: status %d", name, ex.resp.StatusCode)
		}
	}

	// Scopes and tenants.
	k, _ := e.call(e.admin, "POST", "/v1/keys", map[string]any{"client_id": e.clientID.String(), "name": "reader", "scopes": []string{"assets:read"}}, 201)
	reader := k["key"].(string)
	e.apiKeys = append(e.apiKeys, reader)
	e.call(reader, "PATCH", path, map[string]any{"ttl_seconds": 600}, 403)
	e.call(reader, "DELETE", path, nil, 403)
	e.call(other, "PATCH", path, map[string]any{"ttl_seconds": 600}, 404)
	e.call(other, "DELETE", path, nil, 404)
	e.call(e.admin, "PATCH", "/v1/assets/ast_00000000000000000000000000", map[string]any{"ttl_seconds": 600}, 404)
	if got := e.dbAsset(plainID); got.State == db.AssetDeleting || got.ExpiresAt != nil {
		t.Fatal("a refused request changed the asset")
	}
}
