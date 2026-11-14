package contract

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// emptyStore knows no keys.
type emptyStore struct{}

func (emptyStore) GetActiveAPIKeyByPrefix(context.Context, string) (db.AuthKey, error) {
	return db.AuthKey{}, errs.New(errs.NotFound, "resource not found")
}

func (emptyStore) TouchAPIKeyLastUsed(context.Context, id.APIKeyID, time.Time) error { return nil }

type onePepper struct{}

func (onePepper) Get(v int) (config.Secret, bool) {
	return config.NewSecret(strings.Repeat("p", 32)), v == 1
}

func (onePepper) Current() (int, config.Secret) { return 1, config.NewSecret(strings.Repeat("p", 32)) }

// TestScopeTableMatchesSpec asserts that the Go scope table the server enforces equals the
// `security` requirements in the spec, in both directions.
func TestScopeTableMatchesSpec(t *testing.T) {
	doc := loadSpec(t)
	table := api.OperationScopes()
	public := api.PublicOperations()

	seen := map[string]bool{}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if !slices.Contains(op.Tags, "api") {
				continue
			}
			where := method + " " + path
			secured := op.Security != nil && len(*op.Security) > 0
			if !secured {
				if !slices.Contains(public, op.OperationID) {
					t.Errorf("%s (%s) has no security in the spec and is not a public operation in Go", where, op.OperationID)
				}
				continue
			}
			seen[op.OperationID] = true
			reqs := *op.Security
			if len(reqs) != 1 {
				t.Errorf("%s: expected exactly one security requirement, got %d", where, len(reqs))
				continue
			}
			scopes, ok := reqs[0]["bearerAuth"]
			if !ok || len(reqs[0]) != 1 {
				t.Errorf("%s: security must be bearerAuth only", where)
				continue
			}
			want, ok := table[op.OperationID]
			if !ok {
				t.Errorf("%s (%s) is secured in the spec but missing from the Go scope table", where, op.OperationID)
				continue
			}
			got := slices.Clone(scopes)
			sort.Strings(got)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Errorf("%s: spec scopes %v != Go scopes %v", where, got, want)
			}
			for _, s := range scopes {
				if !db.Scope(s).Valid() {
					t.Errorf("%s: unknown scope %q in the spec", where, s)
				}
			}
		}
	}
	for op := range table {
		if !seen[op] {
			t.Errorf("Go scope table has %q, which is not a secured api operation in the spec", op)
		}
	}
	for _, op := range public {
		found := false
		for _, item := range doc.Paths.Map() {
			for _, o := range item.Operations() {
				if o.OperationID == op && (o.Security == nil || len(*o.Security) == 0) {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("public operation %q is not an unsecured operation in the spec", op)
		}
	}
	// The spec's scope enum is the scope set.
	var enum []string
	for _, v := range doc.Components.Schemas["Scope"].Value.Enum {
		enum = append(enum, v.(string))
	}
	var all []string
	for _, s := range auth.AllScopes() {
		all = append(all, string(s))
	}
	sort.Strings(enum)
	sort.Strings(all)
	if !slices.Equal(enum, all) {
		t.Errorf("Scope enum %v != auth.AllScopes() %v", enum, all)
	}
}

// TestSecuredOperationsRequireAuthentication calls every secured operation without a key and with
// a malformed one: 401 with WWW-Authenticate, a valid Problem, and no handler reached (the
// manager is nil, so reaching a handler would panic into a 500).
func TestSecuredOperationsRequireAuthentication(t *testing.T) {
	doc := loadSpec(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := api.New(api.Deps{Log: log, Verifier: auth.NewVerifier(emptyStore{}, onePepper{}, log, nil)})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)

	keyID := "key_" + strings.Repeat("0", 26)
	assetID := "ast_" + strings.Repeat("0", 26)
	sessionID := "ses_" + strings.Repeat("0", 52)
	n := 0
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if op.Security == nil || len(*op.Security) == 0 || !slices.Contains(op.Tags, "api") {
				continue
			}
			p := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(path, "{key_id}", keyID), "{session_id}", sessionID), "{asset_id}", assetID), "{kid}", "key-1")
			var body []byte
			if op.RequestBody != nil && op.RequestBody.Value.Required {
				body = []byte(`{"name":"x"}`)
				switch op.OperationID {
				case "createKey":
					body = []byte(`{"name":"x","client_id":"cli_` + strings.Repeat("0", 26) + `"}`)
				case "createAsset":
					body = []byte(`{"size_bytes":1,"upload_method":"tus"}`)
				case "updatePlaybackSettings":
					body = []byte(`{}`)
				case "updatePrivacySettings":
					body = []byte(`{"store_ip":false,"store_user_agent":false}`)
				case "updatePlaybackAuth":
					body = []byte(`{"jwt_enabled":false,"callback_enabled":false}`)
				case "putPlaybackJwtKey":
					body = []byte(`{"kty":"OKP","alg":"EdDSA"}`)
				case "verifyArtifact":
					body = []byte(`{"sha256":"` + strings.Repeat("0", 64) + `"}`)
				case "revokePlaybackSessions":
					body = []byte(`{"viewer_id":"viewer"}`)
				case "createPlaybackSession":
					body = []byte(`{"asset_id":"` + assetID + `","viewer_id":"viewer"}`)
				}
			}
			for name, hdr := range map[string]map[string]string{
				"no header":  nil,
				"malformed":  {"Authorization": "Bearer nope"},
				"wrong kind": {"Authorization": "Basic abc"},
			} {
				ex := doBody(t, srv.URL, method, p, hdr, body)
				if ex.resp.StatusCode != 401 {
					t.Fatalf("%s %s (%s): status %d, body %s", method, path, name, ex.resp.StatusCode, ex.body)
				}
				if ex.resp.Header.Get("WWW-Authenticate") != "Bearer" {
					t.Fatalf("%s %s (%s): WWW-Authenticate = %q", method, path, name, ex.resp.Header.Get("WWW-Authenticate"))
				}
				if got := validate(t, doc, ex); got != op.OperationID {
					t.Fatalf("matched %q, want %q", got, op.OperationID)
				}
			}
			n++
		}
	}
	if n != 35 {
		t.Fatalf("exercised %d secured operations, want 35", n)
	}
}

// TestUploadOperationsRequireAnUploadToken calls every edge operation secured by the upload
// token without a token, with a malformed one and with an API key (which is never accepted
// there): 401 with WWW-Authenticate, a valid Problem, and no handler reached.
func TestUploadOperationsRequireAnUploadToken(t *testing.T) {
	doc := loadSpec(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := edge.New(edge.Deps{Log: log, Uploads: &edge.Uploads{}})
	srv := httptest.NewServer(e.Handler())
	t.Cleanup(srv.Close)

	assetID := "ast_" + strings.Repeat("0", 26)
	apiKey := "cf_" + strings.Repeat("a", 12) + "_" + strings.Repeat("b", 43)
	n := 0
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if op.Security == nil || len(*op.Security) == 0 || !slices.Contains(op.Tags, "edge") {
				continue
			}
			if _, ok := (*op.Security)[0]["playbackToken"]; ok {
				continue // the playback routes have their own tests (playback_integration_test.go)
			}
			if slices.ContainsFunc(*op.Security, func(r openapi3.SecurityRequirement) bool { _, ok := r["viewerJwt"]; return ok }) {
				continue // the browser-session route authenticates inside its handler (edge_viewer_integration_test.go)
			}
			if _, ok := (*op.Security)[0]["uploadToken"]; !ok {
				t.Errorf("%s %s: edge operations must use the uploadToken scheme", method, path)
				continue
			}
			p := strings.ReplaceAll(strings.ReplaceAll(path, "{asset_id}", assetID), "{part_number}", "1")
			var body []byte
			if op.RequestBody != nil && op.RequestBody.Value.Required {
				body = []byte("part bytes")
			}
			for name, hdr := range map[string]map[string]string{
				"no header":  {"Content-Type": "application/octet-stream"},
				"malformed":  {"Content-Type": "application/octet-stream", "Authorization": "Bearer nope"},
				"api key":    {"Content-Type": "application/octet-stream", "Authorization": "Bearer " + apiKey},
				"wrong kind": {"Content-Type": "application/octet-stream", "Authorization": "Basic abc"},
			} {
				ex := doBody(t, srv.URL, method, p, hdr, body)
				if ex.resp.StatusCode != 401 {
					t.Fatalf("%s %s (%s): status %d, body %s", method, path, name, ex.resp.StatusCode, ex.body)
				}
				if ex.resp.Header.Get("WWW-Authenticate") != "Bearer" {
					t.Fatalf("%s %s (%s): WWW-Authenticate = %q", method, path, name, ex.resp.Header.Get("WWW-Authenticate"))
				}
				if got := validate(t, doc, ex); got != op.OperationID {
					t.Fatalf("matched %q, want %q", got, op.OperationID)
				}
			}
			n++
		}
	}
	if n != 2 {
		t.Fatalf("exercised %d upload operations, want 2", n)
	}
}
