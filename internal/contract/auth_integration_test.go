//go:build integration

package contract

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
)

func TestMain(m *testing.M) {
	code := dbtest.Run(m)
	storagetest.Terminate()
	os.Exit(code)
}

// TestManagementOperationsMatchSpec exercises every secured operation against a real database
// through the real handler chain, and validates each request and response (success and the
// 400, 401, 403 and 404 problems) against the spec.
func TestManagementOperationsMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	pool := dbtest.NewMigrated(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	repos := db.New(pool)
	a := api.New(api.Deps{
		Log:      log,
		Verifier: auth.NewVerifier(repos, onePepper{}, log, nil),
		Manager:  auth.NewManager(pool, onePepper{}, nil),
	})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)

	res, err := auth.NewManager(pool, onePepper{}, nil).Bootstrap(context.Background(), "contract", "contract client")
	if err != nil {
		t.Fatal(err)
	}
	admin := map[string]string{"Authorization": "Bearer " + res.Secret.Reveal()}
	covered := map[string]bool{}

	call := func(hdr map[string]string, method, path string, body any, wantStatus int) map[string]any {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		ex := doBody(t, srv.URL, method, path, hdr, raw)
		if ex.resp.StatusCode != wantStatus {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, ex.resp.StatusCode, wantStatus, ex.body)
		}
		if op := validate(t, doc, ex); op != "" && wantStatus < 300 {
			covered[op] = true
		}
		if wantStatus == 401 && ex.resp.Header.Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("401 without WWW-Authenticate")
		}
		var m map[string]any
		_ = json.Unmarshal(ex.body, &m)
		return m
	}

	call(admin, "GET", "/v1/whoami", nil, 200)
	cli := call(admin, "POST", "/v1/clients", map[string]any{"name": "svc"}, 201)
	call(admin, "GET", "/v1/clients", nil, 200)
	call(admin, "GET", "/v1/clients?limit=1", nil, 200)
	created := call(admin, "POST", "/v1/keys", map[string]any{"client_id": cli["id"], "name": "k", "scopes": []string{"assets:read"}}, 201)
	call(admin, "POST", "/v1/keys", map[string]any{"client_id": cli["id"], "name": "k2"}, 201)
	call(admin, "GET", "/v1/keys", nil, 200)
	call(admin, "GET", "/v1/keys?limit=1", nil, 200)
	keyPath := "/v1/keys/" + created["id"].(string)
	call(admin, "POST", keyPath+"/rotate", nil, 200)
	rotated := call(admin, "POST", keyPath+"/rotate", map[string]any{"overlap_seconds": 5}, 200)
	reader := map[string]string{"Authorization": "Bearer " + rotated["key"].(string)}
	call(reader, "GET", "/v1/whoami", nil, 200)
	selfRotated := call(reader, "POST", keyPath+"/rotate", map[string]any{"overlap_seconds": 0}, 200) // self-rotation
	reader = map[string]string{"Authorization": "Bearer " + selfRotated["key"].(string)}

	// Requests that break the spec's own constraints are sent without request validation; the
	// 400 answer must still be a valid Problem.
	bad := func(method, path string, body any) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		ex := doBody(t, srv.URL, method, path, admin, raw)
		if ex.resp.StatusCode != 400 {
			t.Fatalf("%s %s: status %d, want 400: %s", method, path, ex.resp.StatusCode, ex.body)
		}
		validateProblem(t, doc, ex)
	}

	// Problems.
	call(nil, "GET", "/v1/whoami", nil, 401)
	call(map[string]string{"Authorization": "Bearer cf_bad"}, "GET", "/v1/whoami", nil, 401)
	call(reader, "POST", "/v1/clients", map[string]any{"name": "x"}, 403)
	call(reader, "GET", "/v1/keys", nil, 403)
	bad("POST", "/v1/clients", map[string]any{"name": ""})
	bad("GET", "/v1/clients?limit=0", nil)
	bad("POST", "/v1/keys", map[string]any{"client_id": cli["id"], "name": "x", "scopes": []string{"admin", "admin"}})
	call(admin, "POST", "/v1/keys", map[string]any{"client_id": id.New[id.ClientKind]().String(), "name": "x"}, 404)
	call(admin, "POST", "/v1/keys/key_"+strings.Repeat("0", 26)+"/rotate", nil, 404)
	call(admin, "POST", "/v1/keys/key_"+strings.Repeat("0", 26)+"/revoke", nil, 404)
	other := call(admin, "POST", "/v1/keys", map[string]any{"client_id": cli["id"], "name": "other"}, 201)
	call(reader, "POST", "/v1/keys/"+other["id"].(string)+"/rotate", nil, 403)

	call(admin, "POST", keyPath+"/revoke", nil, 200)
	call(reader, "GET", "/v1/whoami", nil, 401) // revoked

	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if strings.HasPrefix(path, "/v1/assets") || strings.HasPrefix(path, "/v1/uploads/") {
				continue // exercised, with storage, by TestUploadLifecycleAndSourceIsNeverAddressable
			}
			if strings.HasPrefix(path, "/v1/playback-") {
				continue // exercised by TestPlaybackOperationsMatchSpec
			}
			if strings.HasPrefix(path, "/v1/play/") {
				continue // exercised by TestEdgePlaybackOperationsMatchSpec
			}
			if op.Security != nil && len(*op.Security) > 0 && !covered[op.OperationID] {
				t.Errorf("%s %s (%s) was not exercised with a 2xx response", method, path, op.OperationID)
			}
		}
	}
	if keys := mapKeys(covered); !slices.Contains(keys, "rotateKey") {
		t.Fatalf("covered operations: %v", keys)
	}
}

func mapKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
