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

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
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
	n := 0
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if op.Security == nil || len(*op.Security) == 0 || !slices.Contains(op.Tags, "api") {
				continue
			}
			p := strings.ReplaceAll(path, "{key_id}", keyID)
			var body []byte
			if op.RequestBody != nil && op.RequestBody.Value.Required {
				body = []byte(`{"name":"x"}`)
				if op.OperationID == "createKey" {
					body = []byte(`{"name":"x","client_id":"cli_` + strings.Repeat("0", 26) + `"}`)
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
	if n != 7 {
		t.Fatalf("exercised %d secured operations, want 7", n)
	}
}
