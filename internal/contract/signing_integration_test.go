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

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
)

// TestSigningKeyOperationsMatchSpec exercises the signing key operations and the public key set,
// on both listeners, against a real database, and validates every request and response against
// the spec.
func TestSigningKeyOperationsMatchSpec(t *testing.T) {
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
	mgr := signing.NewManager(pool, reg, log)
	t.Cleanup(mgr.Close)
	// A 1 ns TTL keeps the key set in step with the calls below.
	keyset := signing.NewKeySet(repos, 1, nil)
	if err := mgr.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	am := auth.NewManager(pool, onePepper{}, nil)
	res, err := am.Bootstrap(ctx, "contract", "contract client")
	if err != nil {
		t.Fatal(err)
	}
	apiSrv := httptest.NewServer(api.New(api.Deps{
		Log: log, Verifier: auth.NewVerifier(repos, onePepper{}, log, nil), Manager: am, Signing: mgr, KeySet: keyset,
	}).Handler())
	t.Cleanup(apiSrv.Close)
	edgeSrv := httptest.NewServer(edge.New(edge.Deps{Log: log, KeySet: keyset}).Handler())
	t.Cleanup(edgeSrv.Close)

	admin := map[string]string{"Authorization": "Bearer " + res.Secret.Reveal()}
	covered := map[string]bool{}
	call := func(base string, hdr map[string]string, method, path string, wantStatus int) map[string]any {
		t.Helper()
		ex := doBody(t, base, method, path, hdr, nil)
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

	list := call(apiSrv.URL, admin, "GET", "/v1/signing-keys", 200)
	first := list["items"].([]any)[0].(map[string]any)["key_id"].(string)
	rot := call(apiSrv.URL, admin, "POST", "/v1/signing-keys/rotate", 201)
	call(apiSrv.URL, admin, "POST", "/v1/signing-keys/"+rot["key_id"].(string)+"/retire", 409)
	call(apiSrv.URL, admin, "POST", "/v1/signing-keys/"+first+"/retire", 200)
	call(apiSrv.URL, admin, "POST", "/v1/signing-keys/sk_00000000000000000000000001/retire", 404)
	call(apiSrv.URL, nil, "GET", "/v1/signing-keys", 401)

	for _, base := range []string{apiSrv.URL, edgeSrv.URL} {
		set := call(base, nil, "GET", "/.well-known/cipherframe-keys.json", 200)
		keys := set["keys"].([]any)
		if len(keys) != 2 {
			t.Fatalf("%s: key set = %v", base, set)
		}
		if k := keys[0].(map[string]any); k["keyid"] != first || k["status"] != "retired" || k["retired_at"] == nil {
			t.Fatalf("%s: first key = %v", base, k)
		}
		if k := keys[1].(map[string]any); k["keyid"] != rot["key_id"] || k["status"] != "active" {
			t.Fatalf("%s: second key = %v", base, k)
		}
	}
	for _, op := range []string{"listSigningKeys", "rotateSigningKey", "retireSigningKey", "getSigningKeySet"} {
		if !covered[op] {
			t.Errorf("operation %s was not exercised", op)
		}
	}
}
