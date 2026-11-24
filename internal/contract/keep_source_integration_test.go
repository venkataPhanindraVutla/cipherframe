//go:build integration

package contract

import (
	"context"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

// keep_source is copied onto the asset when it is created (H-3): a later change of the tenant's
// setting reaches new uploads only. (The setting's own endpoint is checked against the spec in
// TestAccessLogAndPrivacyOperationsMatchSpec.)
func TestKeepSourceSnapshot(t *testing.T) {
	e := newUpEnv(t)
	body := map[string]any{"size_bytes": 100, "upload_method": "multipart"}
	setDrop := func(drop bool) {
		t.Helper()
		if _, err := e.repos.PutPrivacySettings(context.Background(), e.tenant.ID, db.PrivacySettings{DropSource: drop}, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	create := func() db.Asset {
		t.Helper()
		m, _ := e.call(e.admin, "POST", "/v1/assets", body, 201)
		a := m["asset"].(map[string]any)
		if _, has := a["source_deleted_at"]; has {
			t.Fatalf("a new asset has source_deleted_at: %v", a)
		}
		return e.dbAsset(a["id"].(string))
	}

	// The default keeps the original, for a tenant that never stored a setting.
	kept := create()
	if !kept.KeepSource {
		t.Fatal("the default asset does not keep its source")
	}
	// Off: new assets drop it, the one that exists does not change.
	setDrop(true)
	dropped := create()
	if dropped.KeepSource || !e.dbAsset(kept.ID.String()).KeepSource {
		t.Fatalf("after turning it off: new keeps=%v, old keeps=%v", dropped.KeepSource, e.dbAsset(kept.ID.String()).KeepSource)
	}
	// Back on: the asset created while it was off still drops.
	setDrop(false)
	if e.dbAsset(dropped.ID.String()).KeepSource || !create().KeepSource {
		t.Fatal("changing the setting back changed an existing asset, or did not reach a new one")
	}
}
