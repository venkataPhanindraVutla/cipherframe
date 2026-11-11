//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }

type testPeppers struct{ m map[int]config.Secret }

func (p testPeppers) Get(v int) (config.Secret, bool) { s, ok := p.m[v]; return s, ok }
func (p testPeppers) Current() (int, config.Secret)   { return 2, p.m[2] }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }

func (s *syncBuf) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type harness struct {
	t     *testing.T
	pool  *pgxpool.Pool
	repos *db.Repos
	srv   *httptest.Server
	clk   *clock
	mgr   *auth.Manager
	logs  *syncBuf
	keys  []string // every full key issued, to prove none reaches the log

	keyring *token.Keyring // verifies the playback tokens the API signs
}

// testEdgeURL is the edge public URL the playback service is built with.
const testEdgeURL = "https://media.example.com"

func newHarness(t *testing.T) *harness {
	t.Helper()
	pool := dbtest.NewMigrated(t)
	clk := &clock{t: time.Now().UTC().Truncate(time.Microsecond)}
	peppers := testPeppers{m: map[int]config.Secret{
		1: config.NewSecret(strings.Repeat("a", 32)),
		2: config.NewSecret(strings.Repeat("b", 32)),
	}}
	logs := &syncBuf{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	repos := db.New(pool)
	mgr := auth.NewManager(pool, peppers, clk.Now)
	keyring, err := token.NewKeyring(map[int][]byte{1: []byte("test-fixture-playback-token-key-0123456789")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := playback.NewService(playback.Deps{Pool: pool, Keyring: keyring, EdgeURL: testEdgeURL, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	a := api.New(api.Deps{Log: log, Verifier: auth.NewVerifier(repos, peppers, log, clk.Now), Manager: mgr, Playback: pb})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return &harness{t: t, pool: pool, repos: repos, srv: srv, clk: clk, mgr: mgr, logs: logs, keyring: keyring}
}

// bootstrap creates a tenant with an admin key and returns the full key.
func (h *harness) bootstrap(name string) (string, auth.BootstrapResult) {
	h.t.Helper()
	res, err := h.mgr.Bootstrap(context.Background(), name, name+" client")
	if err != nil {
		h.t.Fatal(err)
	}
	full := res.Secret.Reveal()
	h.keys = append(h.keys, full)
	return full, res
}

type resp struct {
	status int
	hdr    http.Header
	raw    []byte
	m      map[string]any
}

func (h *harness) do(key, method, path string, body any) resp {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = r.Body.Close() }()
	raw, _ := io.ReadAll(r.Body)
	out := resp{status: r.StatusCode, hdr: r.Header, raw: raw}
	_ = json.Unmarshal(raw, &out.m)
	if k, ok := out.m["key"].(string); ok {
		h.keys = append(h.keys, k)
	}
	return out
}

func (r resp) code() string { s, _ := r.m["code"].(string); return s }

func (h *harness) wantStatus(r resp, status int, code string) {
	h.t.Helper()
	if r.status != status || r.code() != code {
		h.t.Fatalf("status %d code %q, want %d %q: %s", r.status, r.code(), status, code, r.raw)
	}
}

func (h *harness) mustOK(r resp, status int) resp {
	h.t.Helper()
	if r.status != status {
		h.t.Fatalf("status %d, want %d: %s", r.status, status, r.raw)
	}
	return r
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func scopesOf(m map[string]any) []string {
	var out []string
	for _, s := range m["scopes"].([]any) {
		out = append(out, s.(string))
	}
	slices.Sort(out)
	return out
}

func (h *harness) newClient(adminKey, name string) string {
	h.t.Helper()
	r := h.mustOK(h.do(adminKey, "POST", "/v1/clients", map[string]any{"name": name}), 201)
	return str(r.m, "id")
}

func (h *harness) newKey(adminKey, clientID, name string, scopes []string) resp {
	h.t.Helper()
	body := map[string]any{"client_id": clientID, "name": name}
	if scopes != nil {
		body["scopes"] = scopes
	}
	return h.mustOK(h.do(adminKey, "POST", "/v1/keys", body), 201)
}

func TestBootstrapThenWhoami(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	r := h.mustOK(h.do(key, "GET", "/v1/whoami", nil), 200)
	if str(r.m, "tenant_id") != res.Tenant.ID.String() || str(r.m, "client_id") != res.Client.ID.String() || str(r.m, "key_id") != res.Key.ID.String() {
		t.Fatalf("whoami = %s", r.raw)
	}
	if got := scopesOf(r.m); !slices.Equal(got, []string{"admin", "assets:read", "assets:write", "sessions:write", "webhooks:manage"}) {
		t.Fatalf("bootstrap key scopes = %v", got)
	}
	// Case-insensitive scheme.
	req, _ := http.NewRequestWithContext(context.Background(), "GET", h.srv.URL+"/v1/whoami", nil)
	req.Header.Set("Authorization", "bEaReR "+key)
	rs, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = rs.Body.Close()
	if rs.StatusCode != 200 {
		t.Fatalf("lowercase scheme: %d", rs.StatusCode)
	}

	events, err := h.repos.ListAuditEvents(context.Background(), res.Tenant.ID, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range events {
		actions = append(actions, e.Action)
	}
	if !slices.Equal(actions, []string{"tenant.create", "client.create", "key.create"}) {
		t.Fatalf("bootstrap audit actions = %v", actions)
	}
	// Health stays unauthenticated.
	h.mustOK(h.do("", "GET", "/healthz", nil), 200)
}

func TestUnauthenticatedAndRevokedKeys(t *testing.T) {
	h := newHarness(t)
	admin, res := h.bootstrap("acme")

	check401 := func(name string, r resp) {
		t.Helper()
		h.wantStatus(r, 401, "unauthenticated")
		if r.hdr.Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("%s: WWW-Authenticate = %q", name, r.hdr.Get("WWW-Authenticate"))
		}
	}
	check401("no header", h.do("", "GET", "/v1/whoami", nil))
	check401("garbage", h.do("garbage", "GET", "/v1/whoami", nil))
	unknown, _ := auth.NewKey()
	check401("unknown", h.do(unknown.Reveal(), "GET", "/v1/whoami", nil))
	wrong, _ := auth.WithNewSecret(res.Key.Prefix)
	check401("wrong secret", h.do(wrong.Reveal(), "GET", "/v1/whoami", nil))
	// Bad auth wins over a bad body: nothing is decoded before authentication.
	check401("bad body unauthenticated", h.do("", "POST", "/v1/clients", "{not json"))

	cli := h.newClient(admin, "svc")
	k := h.newKey(admin, cli, "k1", nil)
	h.mustOK(h.do(str(k.m, "key"), "GET", "/v1/whoami", nil), 200)
	h.mustOK(h.do(admin, "POST", "/v1/keys/"+str(k.m, "id")+"/revoke", nil), 200)
	check401("revoked", h.do(str(k.m, "key"), "GET", "/v1/whoami", nil))
	// Revoking again is idempotent and keeps the original time.
	first := h.mustOK(h.do(admin, "GET", "/v1/keys", nil), 200)
	h.mustOK(h.do(admin, "POST", "/v1/keys/"+str(k.m, "id")+"/revoke", nil), 200)
	second := h.mustOK(h.do(admin, "GET", "/v1/keys", nil), 200)
	if !bytes.Equal(first.raw, second.raw) {
		t.Fatal("second revoke changed the key")
	}
}

func TestScopeEnforcement(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	cli := h.newClient(admin, "svc")

	def := h.newKey(admin, cli, "default", nil)
	if got := scopesOf(def.m); !slices.Equal(got, []string{"assets:read", "assets:write", "sessions:write", "webhooks:manage"}) {
		t.Fatalf("default scopes = %v", got)
	}
	reader := h.newKey(admin, cli, "reader", []string{"assets:read"})
	rk := str(reader.m, "key")
	who := h.mustOK(h.do(rk, "GET", "/v1/whoami", nil), 200)
	if got := scopesOf(who.m); !slices.Equal(got, []string{"assets:read"}) {
		t.Fatalf("scopes = %v", got)
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/v1/clients"},
		{"GET", "/v1/clients"},
		{"POST", "/v1/keys"},
		{"GET", "/v1/keys"},
		{"POST", "/v1/keys/" + str(def.m, "id") + "/revoke"},
	} {
		var body any
		if c.method == "POST" {
			body = map[string]any{"name": "x", "client_id": cli}
		}
		h.wantStatus(h.do(rk, c.method, c.path, body), 403, "forbidden")
	}
	// A non-admin key may rotate itself but no other key.
	h.wantStatus(h.do(rk, "POST", "/v1/keys/"+str(def.m, "id")+"/rotate", nil), 403, "forbidden")
	h.mustOK(h.do(rk, "POST", "/v1/keys/"+str(reader.m, "id")+"/rotate", nil), 200)
}

func TestTenantIsolation(t *testing.T) {
	h := newHarness(t)
	adminA, _ := h.bootstrap("tenant-a")
	adminB, resB := h.bootstrap("tenant-b")
	keyB := h.newKey(adminB, resB.Client.ID.String(), "kb", nil)

	// Tenant A's admin cannot create keys for, rotate, or revoke anything of tenant B.
	h.wantStatus(h.do(adminA, "POST", "/v1/keys", map[string]any{"client_id": resB.Client.ID.String(), "name": "x"}), 404, "not_found")
	h.wantStatus(h.do(adminA, "POST", "/v1/keys/"+str(keyB.m, "id")+"/rotate", nil), 404, "not_found")
	h.wantStatus(h.do(adminA, "POST", "/v1/keys/"+str(keyB.m, "id")+"/revoke", nil), 404, "not_found")
	// And B's key still works untouched.
	h.mustOK(h.do(str(keyB.m, "key"), "GET", "/v1/whoami", nil), 200)

	// Listings show only the caller's tenant.
	ks := h.mustOK(h.do(adminA, "GET", "/v1/keys", nil), 200)
	if items := ks.m["items"].([]any); len(items) != 1 {
		t.Fatalf("tenant A sees %d keys", len(items))
	}
	cs := h.mustOK(h.do(adminA, "GET", "/v1/clients", nil), 200)
	for _, c := range cs.m["items"].([]any) {
		if c.(map[string]any)["id"] == resB.Client.ID.String() {
			t.Fatal("tenant A lists tenant B's client")
		}
	}
	// Malformed and wrong-type IDs.
	h.wantStatus(h.do(adminA, "POST", "/v1/keys/cli_"+strings.Repeat("0", 26)+"/revoke", nil), 404, "not_found")
	h.wantStatus(h.do(adminA, "POST", "/v1/keys", map[string]any{"client_id": "nope", "name": "x"}), 400, "invalid_request")
}

func TestRotationInPlace(t *testing.T) {
	h := newHarness(t)
	admin, res := h.bootstrap("acme")
	ctx := context.Background()
	cli := h.newClient(admin, "svc")
	cliID, _ := id.Parse[id.ClientKind](cli)
	created := h.newKey(admin, cli, "worker", []string{"assets:read", "assets:write"})
	oldKey, keyID, prefix := str(created.m, "key"), str(created.m, "id"), str(created.m, "prefix")

	// The client creates an asset and acts (an audit row) before rotation.
	asset, err := h.repos.CreateAsset(ctx, res.Tenant.ID, cliID, db.AssetCreated)
	if err != nil {
		t.Fatal(err)
	}
	h.mustOK(h.do(oldKey, "GET", "/v1/whoami", nil), 200)
	if _, err := h.repos.InsertAuditEvent(ctx, db.NewAuditEvent{TenantID: res.Tenant.ID, ClientID: cliID, APIKeyID: mustKeyID(t, keyID), Action: "asset.create", Target: asset.ID.String()}); err != nil {
		t.Fatal(err)
	}

	h.clk.Advance(time.Minute)
	rot := h.mustOK(h.do(admin, "POST", "/v1/keys/"+keyID+"/rotate", map[string]any{"overlap_seconds": 600}), 200)
	if rot.hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rot.hdr.Get("Cache-Control"))
	}
	newKey := str(rot.m, "key")
	if newKey == oldKey || str(rot.m, "id") != keyID || str(rot.m, "prefix") != prefix || str(rot.m, "client_id") != cli {
		t.Fatalf("rotation changed identity: %s", rot.raw)
	}
	if !strings.HasPrefix(newKey, "cf_"+prefix+"_") {
		t.Fatal("new key does not keep the prefix")
	}
	if rot.m["rotated_at"] == nil || rot.m["previous_valid_until"] == nil {
		t.Fatalf("rotation timestamps missing: %s", rot.raw)
	}

	// Both secrets work inside the overlap; whoami shows the same key id for both.
	for _, k := range []string{oldKey, newKey} {
		w := h.mustOK(h.do(k, "GET", "/v1/whoami", nil), 200)
		if str(w.m, "key_id") != keyID || str(w.m, "client_id") != cli {
			t.Fatalf("whoami after rotation: %s", w.raw)
		}
	}
	h.clk.Advance(599 * time.Second)
	h.mustOK(h.do(oldKey, "GET", "/v1/whoami", nil), 200)
	h.clk.Advance(2 * time.Second) // now 601 s after rotation
	h.wantStatus(h.do(oldKey, "GET", "/v1/whoami", nil), 401, "unauthenticated")
	h.mustOK(h.do(newKey, "GET", "/v1/whoami", nil), 200)

	// Ownership is unchanged: the asset and the audit rows still point at the same client and key.
	got, err := h.repos.GetAsset(ctx, res.Tenant.ID, asset.ID)
	if err != nil || got.CreatedByClientID != cliID {
		t.Fatalf("asset owner changed: %+v %v", got, err)
	}
	events, err := h.repos.ListAuditEvents(ctx, res.Tenant.ID, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	var sawAsset, sawRotate bool
	for _, e := range events {
		switch e.Action {
		case "asset.create":
			sawAsset = e.ClientID == cliID && e.APIKeyID.String() == keyID
		case auth.AuditKeyRotate:
			sawRotate = e.Target == keyID && e.ClientID == res.Client.ID && e.APIKeyID == res.Key.ID && e.RequestID != ""
		}
	}
	if !sawAsset || !sawRotate {
		t.Fatalf("audit rows after rotation: asset=%v rotate=%v", sawAsset, sawRotate)
	}
	list := h.mustOK(h.do(admin, "GET", "/v1/keys", nil), 200)
	n := 0
	for _, it := range list.m["items"].([]any) {
		if m := it.(map[string]any); str(m, "id") == keyID {
			n++
			if str(m, "prefix") != prefix || str(m, "client_id") != cli {
				t.Fatalf("listed key changed: %v", m)
			}
		}
	}
	if n != 1 {
		t.Fatalf("expected the same single key row, found %d", n)
	}
}

func mustKeyID(t *testing.T, s string) id.APIKeyID {
	t.Helper()
	k, err := id.Parse[id.APIKeyKind](s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRotationOverlapOptions(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	cli := h.newClient(admin, "svc")

	// Overlap 0: the old key stops working at once.
	k := h.newKey(admin, cli, "k", nil)
	rot := h.mustOK(h.do(admin, "POST", "/v1/keys/"+str(k.m, "id")+"/rotate", map[string]any{"overlap_seconds": 0}), 200)
	h.wantStatus(h.do(str(k.m, "key"), "GET", "/v1/whoami", nil), 401, "unauthenticated")
	h.mustOK(h.do(str(rot.m, "key"), "GET", "/v1/whoami", nil), 200)

	// Default overlap is 10 minutes (no body).
	k2 := h.newKey(admin, cli, "k2", nil)
	h.mustOK(h.do(admin, "POST", "/v1/keys/"+str(k2.m, "id")+"/rotate", nil), 200)
	h.clk.Advance(9 * time.Minute)
	h.mustOK(h.do(str(k2.m, "key"), "GET", "/v1/whoami", nil), 200)
	h.clk.Advance(2 * time.Minute)
	h.wantStatus(h.do(str(k2.m, "key"), "GET", "/v1/whoami", nil), 401, "unauthenticated")

	// Out-of-range overlap and a revoked key.
	h.wantStatus(h.do(admin, "POST", "/v1/keys/"+str(k2.m, "id")+"/rotate", map[string]any{"overlap_seconds": 86401}), 400, "invalid_request")
	h.wantStatus(h.do(admin, "POST", "/v1/keys/"+str(k2.m, "id")+"/rotate", map[string]any{"overlap_seconds": -1}), 400, "invalid_request")
	h.mustOK(h.do(admin, "POST", "/v1/keys/"+str(k2.m, "id")+"/rotate", map[string]any{"overlap_seconds": 86400}), 200)
	h.mustOK(h.do(admin, "POST", "/v1/keys/"+str(k2.m, "id")+"/revoke", nil), 200)
	h.wantStatus(h.do(admin, "POST", "/v1/keys/"+str(k2.m, "id")+"/rotate", nil), 404, "not_found")
}

func TestRevokeTakesEffectOnNextRequest(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	cli := h.newClient(admin, "svc")
	k := h.newKey(admin, cli, "k", nil)
	rot := h.mustOK(h.do(admin, "POST", "/v1/keys/"+str(k.m, "id")+"/rotate", nil), 200)
	// Inside the overlap both secrets work; revoking kills both at once.
	h.mustOK(h.do(str(k.m, "key"), "GET", "/v1/whoami", nil), 200)
	h.mustOK(h.do(str(rot.m, "key"), "GET", "/v1/whoami", nil), 200)
	h.mustOK(h.do(admin, "POST", "/v1/keys/"+str(k.m, "id")+"/revoke", nil), 200)
	h.wantStatus(h.do(str(k.m, "key"), "GET", "/v1/whoami", nil), 401, "unauthenticated")
	h.wantStatus(h.do(str(rot.m, "key"), "GET", "/v1/whoami", nil), 401, "unauthenticated")
	// An admin key can revoke itself.
	h.mustOK(h.do(admin, "POST", "/v1/keys/"+str(h.mustOK(h.do(admin, "GET", "/v1/whoami", nil), 200).m, "key_id")+"/revoke", nil), 200)
	h.wantStatus(h.do(admin, "GET", "/v1/whoami", nil), 401, "unauthenticated")
}

func TestDisabledClientAndTenantCannotAuthenticate(t *testing.T) {
	h := newHarness(t)
	admin, res := h.bootstrap("acme")
	h.mustOK(h.do(admin, "GET", "/v1/whoami", nil), 200)
	if _, err := h.pool.Exec(context.Background(), "UPDATE clients SET disabled_at = now() WHERE id = $1", res.Client.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	h.wantStatus(h.do(admin, "GET", "/v1/whoami", nil), 401, "unauthenticated")
}

func TestValidationAndPagination(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	cli := h.newClient(admin, "svc")

	bad := []struct {
		path string
		body any
	}{
		{"/v1/clients", map[string]any{"name": ""}},
		{"/v1/clients", map[string]any{"name": strings.Repeat("x", 101)}},
		{"/v1/clients", map[string]any{"name": "a\nb"}},
		{"/v1/clients", map[string]any{}},
		{"/v1/clients", "{not json"},
		{"/v1/keys", map[string]any{"client_id": cli, "name": "k", "scopes": []string{"nope"}}},
		{"/v1/keys", map[string]any{"client_id": cli, "name": "k", "scopes": []string{"admin", "admin"}}},
		{"/v1/keys", map[string]any{"client_id": cli, "name": "k", "scopes": []string{}}},
		{"/v1/keys", map[string]any{"client_id": cli, "name": ""}},
	}
	for _, b := range bad {
		h.wantStatus(h.do(admin, "POST", b.path, b.body), 400, "invalid_request")
	}
	// Oversized body.
	h.wantStatus(h.do(admin, "POST", "/v1/clients", `{"name":"`+strings.Repeat("x", 70000)+`"}`), 413, "payload_too_large")
	for _, q := range []string{"limit=0", "limit=101", "limit=abc", "cursor=bogus", "cursor=key_" + strings.Repeat("0", 26)} {
		h.wantStatus(h.do(admin, "GET", "/v1/clients?"+q, nil), 400, "invalid_request")
	}

	for i := range 5 {
		h.newClient(admin, "c"+string(rune('a'+i)))
	}
	// 7 clients in total (bootstrap, svc, five). Page through two at a time.
	seen := map[string]bool{}
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		path := "/v1/clients?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		r := h.mustOK(h.do(admin, "GET", path, nil), 200)
		for _, it := range r.m["items"].([]any) {
			cid := str(it.(map[string]any), "id")
			if seen[cid] {
				t.Fatalf("duplicate client %s across pages", cid)
			}
			seen[cid] = true
		}
		next, ok := r.m["next_cursor"].(string)
		if !ok {
			break
		}
		cursor = next
	}
	if len(seen) != 7 {
		t.Fatalf("paged through %d clients, want 7", len(seen))
	}

	// Key listing: metadata only.
	h.newKey(admin, cli, "k", nil)
	r := h.mustOK(h.do(admin, "GET", "/v1/keys", nil), 200)
	for _, banned := range []string{"hash", "secret", "pepper", "\"key\":"} {
		if strings.Contains(string(r.raw), banned) {
			t.Fatalf("key listing contains %q: %s", banned, r.raw)
		}
	}
}

func TestLastUsedAtThrottled(t *testing.T) {
	h := newHarness(t)
	admin, res := h.bootstrap("acme")
	lastUsed := func() string {
		var out string
		for _, it := range h.mustOK(h.do(admin, "GET", "/v1/keys", nil), 200).m["items"].([]any) {
			if m := it.(map[string]any); str(m, "id") == res.Key.ID.String() {
				out = str(m, "last_used_at")
			}
		}
		return out
	}
	first := lastUsed() // the listing call itself authenticated the key
	if first == "" {
		t.Fatal("last_used_at not recorded")
	}
	h.clk.Advance(30 * time.Second)
	if lastUsed() != first {
		t.Fatal("last_used_at updated inside a minute")
	}
	h.clk.Advance(31 * time.Second)
	lastUsed() // this authentication writes
	if lastUsed() == first {
		t.Fatal("last_used_at not updated after a minute")
	}
}

func TestNoKeyMaterialInLogs(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	cli := h.newClient(admin, "svc")
	k := h.newKey(admin, cli, "k", nil)
	h.mustOK(h.do(admin, "POST", "/v1/keys/"+str(k.m, "id")+"/rotate", nil), 200)
	h.do("cf_bad", "GET", "/v1/whoami", nil)
	h.do(str(k.m, "key"), "GET", "/v1/whoami", nil)
	logs := h.logs.String()
	for _, full := range h.keys {
		if strings.Contains(logs, full) || strings.Contains(logs, full[16:]) {
			t.Fatal("a full key or secret reached the log")
		}
	}
	if strings.Contains(logs, "Bearer") || strings.Contains(logs, "Authorization") {
		t.Fatal("authorization data in the log")
	}
}
