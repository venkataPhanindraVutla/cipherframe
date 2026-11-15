//go:build integration

package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/webhook"
)

// TestWebhookOperationsMatchSpec exercises every webhook operation against a real database through
// the real handler chain and validates each request and response, success and problem, against
// the spec.
func TestWebhookOperationsMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	ctx := context.Background()
	pool := dbtest.NewMigrated(t)
	repos := db.New(pool)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	lp, err := local.NewFromKeys(config.Development, map[int][]byte{1: bytes.Repeat([]byte{0x41}, config.KEKBytes)}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := kms.NewRegistry(lp)
	if err != nil {
		t.Fatal(err)
	}
	hooks, err := webhook.NewService(webhook.ServiceDeps{Pool: pool, KMS: reg})
	if err != nil {
		t.Fatal(err)
	}
	am := auth.NewManager(pool, onePepper{}, nil)
	res, err := am.Bootstrap(ctx, "contract", "contract client")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.New(api.Deps{
		Log: log, Verifier: auth.NewVerifier(repos, onePepper{}, log, nil), Manager: am, Webhooks: hooks,
	}).Handler())
	t.Cleanup(srv.Close)

	admin := map[string]string{"Authorization": "Bearer " + res.Secret.Reveal()}
	covered := map[string]bool{}
	call := func(method, path string, body any, wantStatus int) map[string]any {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		ex := doBody(t, srv.URL, method, path, admin, raw)
		if ex.resp.StatusCode != wantStatus {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, ex.resp.StatusCode, wantStatus, ex.body)
		}
		if op := validate(t, doc, ex); op != "" && wantStatus < 300 {
			covered[op] = true
		}
		var m map[string]any
		_ = json.Unmarshal(ex.body, &m)
		return m
	}

	created := call("POST", "/v1/webhook-endpoints", map[string]any{"url": "https://hooks.example.com/a", "events": []string{"asset.ready"}}, 201)
	eid := created["endpoint"].(map[string]any)["id"].(string)
	call("GET", "/v1/webhook-endpoints", nil, 200)
	call("GET", "/v1/webhook-endpoints/"+eid, nil, 200)
	call("PATCH", "/v1/webhook-endpoints/"+eid, map[string]any{"enabled": true, "events": []string{}}, 200)
	call("POST", "/v1/webhook-endpoints/"+eid+"/rotate-secret", nil, 200)
	call("POST", "/v1/webhook-endpoints", map[string]any{"url": "http://hooks.example.com/a"}, 400)
	call("GET", "/v1/webhook-endpoints/whe_"+"00000000000000000000000001", nil, 404)
	call("POST", "/v1/webhook-endpoints/whe_"+"00000000000000000000000001/replay-dead", nil, 404)

	// One event, so there is a delivery to list, read and replay.
	asset, err := repos.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: res.Tenant.ID, ClientID: res.Client.ID, SizeBytes: 1,
		Method: db.UploadTus, SourceKey: "test-fixture-source", ExpiresAt: time.Now().Add(time.Hour).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []db.AssetState{db.AssetUploading, db.AssetCommitted, db.AssetProcessing, db.AssetReady} {
		if asset, err = repos.TransitionAsset(ctx, res.Tenant.ID, asset.ID, db.Transition{From: asset.State, To: next}); err != nil {
			t.Fatal(err)
		}
	}
	list := call("GET", "/v1/webhook-deliveries", nil, 200)
	did := list["items"].([]any)[0].(map[string]any)["id"].(string)
	call("GET", "/v1/webhook-deliveries?endpoint_id="+eid+"&status=pending&limit=5", nil, 200)
	call("GET", "/v1/webhook-deliveries/"+did, nil, 200)
	call("POST", "/v1/webhook-deliveries/"+did+"/replay", nil, 409) // still pending
	call("GET", "/v1/webhook-deliveries/00000000-0000-4000-8000-000000000000", nil, 404)
	if _, err := pool.Exec(ctx, `UPDATE webhook_deliveries SET state = 'dead', completed_at = now()`); err != nil {
		t.Fatal(err)
	}
	call("POST", "/v1/webhook-deliveries/"+did+"/replay", nil, 202)
	if _, err := pool.Exec(ctx, `UPDATE webhook_deliveries SET state = 'dead', completed_at = now()`); err != nil {
		t.Fatal(err)
	}
	if m := call("POST", "/v1/webhook-endpoints/"+eid+"/replay-dead", nil, 200); m["replayed"] != 1.0 {
		t.Fatalf("replay-dead = %v", m)
	}
	call("DELETE", "/v1/webhook-endpoints/"+eid, nil, 204)

	for _, op := range []string{
		"createWebhookEndpoint", "listWebhookEndpoints", "getWebhookEndpoint", "updateWebhookEndpoint", "deleteWebhookEndpoint",
		"rotateWebhookEndpointSecret", "replayDeadWebhookDeliveries", "listWebhookDeliveries", "getWebhookDelivery", "replayWebhookDelivery",
	} {
		if !covered[op] {
			t.Errorf("operation %s was not exercised", op)
		}
	}
}
