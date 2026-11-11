//go:build integration

package api_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

func fullSettings() map[string]any {
	return map[string]any{
		"token_ttl_seconds": 900, "heartbeat_interval_seconds": 30, "idle_timeout_seconds": 120,
		"session_max_seconds": 7200, "max_sessions_per_viewer": 5, "key_fetches_per_token": 10,
		"key_requests_per_minute": 15, "allowed_origins": []any{"https://app.example.com", "http://localhost:3000"},
		"token_in_url": false, "delivery": "proxy",
	}
}

// fieldErrors returns the field names of a Problem's errors array, in order.
func fieldErrors(r resp) []string {
	var out []string
	list, _ := r.m["errors"].([]any)
	for _, e := range list {
		f, _ := e.(map[string]any)["field"].(string)
		out = append(out, f)
	}
	return out
}

func TestPlaybackSettingsDefaults(t *testing.T) {
	h := newHarness(t)
	key, _ := h.bootstrap("acme")
	r := h.mustOK(h.do(key, "GET", "/v1/playback-settings", nil), 200)
	want := map[string]any{
		"token_ttl_seconds": 600.0, "heartbeat_interval_seconds": 60.0, "idle_timeout_seconds": 300.0,
		"session_max_seconds": 14400.0, "max_sessions_per_viewer": 3.0, "key_fetches_per_token": 20.0,
		"key_requests_per_minute": 30.0, "allowed_origins": []any{}, "token_in_url": false, "delivery": "proxy",
	}
	if !reflect.DeepEqual(r.m, want) {
		t.Fatalf("defaults = %s", r.raw)
	}
	if strings.Contains(string(r.raw), `"allowed_origins":null`) {
		t.Fatal("allowed_origins is null")
	}
}

func TestPlaybackSettingsRoundTrip(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	otherKey, _ := h.bootstrap("other")

	put := h.mustOK(h.do(key, "PUT", "/v1/playback-settings", fullSettings()), 200)
	if _, ok := put.m["updated_at"].(string); !ok {
		t.Fatalf("no updated_at: %s", put.raw)
	}
	got := h.mustOK(h.do(key, "GET", "/v1/playback-settings", nil), 200)
	if !reflect.DeepEqual(got.m, put.m) {
		t.Fatalf("GET %s != PUT %s", got.raw, put.raw)
	}
	want := fullSettings()
	for k, v := range want {
		if !reflect.DeepEqual(got.m[k], v) && !(k != "allowed_origins" && k != "token_in_url" && got.m[k] == float64(v.(int))) {
			t.Errorf("%s = %v, want %v", k, got.m[k], v)
		}
	}

	// A second PUT replaces everything, including emptying the origin list and switching a flag
	// and the limit to their zero values.
	again := fullSettings()
	again["allowed_origins"], again["max_sessions_per_viewer"], again["token_in_url"], again["delivery"] = []any{}, 0, true, "presigned"
	r := h.mustOK(h.do(key, "PUT", "/v1/playback-settings", again), 200)
	if !reflect.DeepEqual(r.m["allowed_origins"], []any{}) || r.m["max_sessions_per_viewer"] != 0.0 || r.m["token_in_url"] != true || r.m["delivery"] != "presigned" {
		t.Fatalf("second PUT = %s", r.raw)
	}

	// Settings belong to the tenant.
	other := h.mustOK(h.do(otherKey, "GET", "/v1/playback-settings", nil), 200)
	if other.m["max_sessions_per_viewer"] != 3.0 || other.m["token_in_url"] != false || other.m["delivery"] != "proxy" {
		t.Fatalf("another tenant's settings = %s", other.raw)
	}
	if _, ok := other.m["updated_at"]; ok {
		t.Fatal("another tenant has an updated_at")
	}

	// Every PUT is audited, with the caller and no setting values.
	var n int
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'playback_settings.update' AND client_id = $2",
		res.Tenant.ID.UUID(), res.Client.ID.UUID()).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit events = %d, %v; want 2", n, err)
	}
}

// The stored settings drive session creation.
func TestPlaybackSettingsApplyToSessions(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)

	s := fullSettings()
	s["token_in_url"], s["max_sessions_per_viewer"], s["heartbeat_interval_seconds"] = true, 2, 45
	h.mustOK(h.do(key, "PUT", "/v1/playback-settings", s), 200)

	r := h.mustOK(h.createSession(key, asset.ID.String(), "v"), 201)
	if str(r.m, "token_transport") != "url" || !strings.HasSuffix(str(r.m, "manifest_url"), "?t="+str(r.m, "token")) ||
		r.m["heartbeat_interval_seconds"] != 45.0 {
		t.Fatalf("session = %s", r.raw)
	}
	h.mustOK(h.createSession(key, asset.ID.String(), "v"), 201)
	h.wantStatus(h.createSession(key, asset.ID.String(), "v"), 409, "session_limit")

	s["max_sessions_per_viewer"], s["token_in_url"] = 0, false
	h.mustOK(h.do(key, "PUT", "/v1/playback-settings", s), 200)
	for range 4 {
		h.mustOK(h.createSession(key, asset.ID.String(), "v"), 201)
	}
}

func TestPlaybackSettingsValidation(t *testing.T) {
	h := newHarness(t)
	key, _ := h.bootstrap("acme")

	with := func(k string, v any) map[string]any {
		s := fullSettings()
		s[k] = v
		return s
	}
	cases := map[string]struct {
		body  map[string]any
		field []string
	}{
		"ttl low":            {with("token_ttl_seconds", 59), []string{"token_ttl_seconds"}},
		"ttl high":           {with("token_ttl_seconds", 3601), []string{"token_ttl_seconds"}},
		"heartbeat low":      {with("heartbeat_interval_seconds", 9), []string{"heartbeat_interval_seconds"}},
		"heartbeat high":     {with("heartbeat_interval_seconds", 601), []string{"heartbeat_interval_seconds"}},
		"idle low":           {with("idle_timeout_seconds", 29), []string{"idle_timeout_seconds"}},
		"idle high":          {with("idle_timeout_seconds", 3601), []string{"idle_timeout_seconds"}},
		"session max low":    {with("session_max_seconds", 299), []string{"session_max_seconds"}},
		"session max high":   {with("session_max_seconds", 86401), []string{"session_max_seconds"}},
		"max sessions neg":   {with("max_sessions_per_viewer", -1), []string{"max_sessions_per_viewer"}},
		"max sessions high":  {with("max_sessions_per_viewer", 101), []string{"max_sessions_per_viewer"}},
		"key fetches zero":   {with("key_fetches_per_token", 0), []string{"key_fetches_per_token"}},
		"key fetches high":   {with("key_fetches_per_token", 1001), []string{"key_fetches_per_token"}},
		"key rpm zero":       {with("key_requests_per_minute", 0), []string{"key_requests_per_minute"}},
		"key rpm high":       {with("key_requests_per_minute", 601), []string{"key_requests_per_minute"}},
		"huge number":        {with("session_max_seconds", 1<<40), []string{"session_max_seconds"}},
		"wildcard origin":    {with("allowed_origins", []any{"https://ok.example.com", "https://*.example.com"}), []string{"allowed_origins[1]"}},
		"unknown delivery":   {with("delivery", "cdn"), []string{"delivery"}},
		"http origin":        {with("allowed_origins", []any{"http://example.com"}), []string{"allowed_origins[0]"}},
		"origin with path":   {with("allowed_origins", []any{"https://example.com/app"}), []string{"allowed_origins[0]"}},
		"origin with slash":  {with("allowed_origins", []any{"https://example.com/"}), []string{"allowed_origins[0]"}},
		"origin credentials": {with("allowed_origins", []any{"https://u:p@example.com"}), []string{"allowed_origins[0]"}},
		"duplicate origin":   {with("allowed_origins", []any{"https://a.example.com", "https://a.example.com"}), []string{"allowed_origins[1]"}},
		"not an origin":      {with("allowed_origins", []any{"example.com", "", "null"}), []string{"allowed_origins[0]", "allowed_origins[1]", "allowed_origins[2]"}},
		"several problems": {func() map[string]any {
			s := with("token_ttl_seconds", 1)
			s["key_fetches_per_token"], s["allowed_origins"] = 0, []any{"*"}
			return s
		}(), []string{"token_ttl_seconds", "key_fetches_per_token", "allowed_origins[0]"}},
	}
	// The relations between the heartbeat and the other two intervals.
	hb := with("token_ttl_seconds", 60)
	hb["heartbeat_interval_seconds"] = 60
	cases["heartbeat >= ttl"] = struct {
		body  map[string]any
		field []string
	}{hb, []string{"heartbeat_interval_seconds"}}
	idle := with("idle_timeout_seconds", 30)
	idle["heartbeat_interval_seconds"] = 30
	cases["heartbeat >= idle"] = struct {
		body  map[string]any
		field []string
	}{idle, []string{"heartbeat_interval_seconds"}}
	tooMany := make([]any, 21)
	for i := range tooMany {
		tooMany[i] = "https://h" + strings.Repeat("a", i+1) + ".example.com"
	}
	cases["21 origins"] = struct {
		body  map[string]any
		field []string
	}{with("allowed_origins", tooMany), []string{"allowed_origins"}}

	for name, c := range cases {
		r := h.do(key, "PUT", "/v1/playback-settings", c.body)
		h.wantStatus(r, 400, "invalid_request")
		got := fieldErrors(r)
		if !reflect.DeepEqual(got, c.field) {
			t.Errorf("%s: field errors = %v, want %v (%s)", name, got, c.field, r.raw)
		}
		for _, o := range []string{"u:p", "example.com/app"} {
			if strings.Contains(string(r.raw), o) {
				t.Errorf("%s: the problem echoes %q: %s", name, o, r.raw)
			}
		}
	}
	// None of the rejected requests stored anything.
	got := h.mustOK(h.do(key, "GET", "/v1/playback-settings", nil), 200)
	if _, ok := got.m["updated_at"]; ok {
		t.Fatalf("a rejected request stored settings: %s", got.raw)
	}

	// The extremes are accepted.
	h.mustOK(h.do(key, "PUT", "/v1/playback-settings", map[string]any{
		"token_ttl_seconds": 60, "heartbeat_interval_seconds": 10, "idle_timeout_seconds": 30,
		"session_max_seconds": 300, "max_sessions_per_viewer": 0, "key_fetches_per_token": 1,
		"key_requests_per_minute": 1, "allowed_origins": []any{}, "token_in_url": true, "delivery": "presigned",
	}), 200)
	h.mustOK(h.do(key, "PUT", "/v1/playback-settings", map[string]any{
		"token_ttl_seconds": 3600, "heartbeat_interval_seconds": 600, "idle_timeout_seconds": 3600,
		"session_max_seconds": 86400, "max_sessions_per_viewer": 100, "key_fetches_per_token": 1000,
		"key_requests_per_minute": 600, "allowed_origins": []any{"https://a.example.com:8443"}, "token_in_url": false, "delivery": "proxy",
	}), 200)
}

func TestPlaybackSettingsMissingFields(t *testing.T) {
	h := newHarness(t)
	key, _ := h.bootstrap("acme")

	r := h.do(key, "PUT", "/v1/playback-settings", `{}`)
	h.wantStatus(r, 400, "invalid_request")
	if len(fieldErrors(r)) != 10 {
		t.Fatalf("empty body: field errors = %v", fieldErrors(r))
	}
	// A zero value is not a missing field; null and absent are.
	s := fullSettings()
	delete(s, "max_sessions_per_viewer")
	s["token_in_url"], s["allowed_origins"], s["delivery"] = nil, nil, nil
	r = h.do(key, "PUT", "/v1/playback-settings", s)
	h.wantStatus(r, 400, "invalid_request")
	if got, want := fieldErrors(r), []string{"max_sessions_per_viewer", "allowed_origins", "token_in_url", "delivery"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("field errors = %v, want %v", got, want)
	}
	h.wantStatus(h.do(key, "PUT", "/v1/playback-settings", `not json`), 400, "invalid_request")
	h.wantStatus(h.do(key, "PUT", "/v1/playback-settings", `{"token_ttl_seconds":"600"}`), 400, "invalid_request")
}

func TestPlaybackSettingsNeedAdmin(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	cli := h.newClient(admin, "svc")
	for name, scopes := range map[string][]string{
		"sessions":             {"sessions:write"},
		"assets":               {"assets:read", "assets:write"},
		"webhooks":             {"webhooks:manage"},
		"everything but admin": {"assets:read", "assets:write", "sessions:write", "webhooks:manage"},
	} {
		k := str(h.newKey(admin, cli, name, scopes).m, "key")
		h.wantStatus(h.do(k, "GET", "/v1/playback-settings", nil), 403, "forbidden")
		h.wantStatus(h.do(k, "PUT", "/v1/playback-settings", fullSettings()), 403, "forbidden")
	}
	h.wantStatus(h.do("", "GET", "/v1/playback-settings", nil), 401, "unauthenticated")
	h.wantStatus(h.do("", "PUT", "/v1/playback-settings", fullSettings()), 401, "unauthenticated")
	// An admin-only key may read and write.
	k := str(h.newKey(admin, cli, "admin", []string{"admin"}).m, "key")
	h.mustOK(h.do(k, "PUT", "/v1/playback-settings", fullSettings()), 200)
	h.mustOK(h.do(k, "GET", "/v1/playback-settings", nil), 200)
	got := h.mustOK(h.do(admin, "GET", "/v1/playback-settings", nil), 200)
	if got.m["max_sessions_per_viewer"] != 5.0 {
		t.Fatalf("settings written by the admin-only key: %s", got.raw)
	}
}
