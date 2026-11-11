//go:build integration

package api_test

import (
	"context"
	"encoding/hex"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// seedEvent stores an event for a session (hash set) or a viewer directly.
func (h *harness) seedEvent(res auth.BootstrapResult, asset db.Asset, hash []byte, viewer, kind string, at time.Time, detail map[string]int64) {
	h.t.Helper()
	ok, err := h.repos.InsertAnomalyEvent(context.Background(), db.NewAnomalyEvent{
		TenantID: res.Tenant.ID, SessionHash: hash, ViewerID: viewer, AssetID: asset.ID, Kind: kind,
		At: at, Since: at.Add(-time.Minute), Detail: detail,
	})
	if err != nil || !ok {
		h.t.Fatalf("seed %s: %v, %v", kind, ok, err)
	}
}

func items(t *testing.T, r resp) []map[string]any {
	t.Helper()
	list, ok := r.m["items"].([]any)
	if !ok {
		t.Fatalf("no items array: %s", r.raw)
	}
	out := make([]map[string]any, len(list))
	for i, it := range list {
		out[i] = it.(map[string]any)
	}
	return out
}

func kinds(its []map[string]any) []string {
	out := make([]string, len(its))
	for i, it := range its {
		out[i] = it["kind"].(string)
	}
	return out
}

func TestPlaybackEventsAPI(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	otherKey, otherRes := h.bootstrap("other")
	a1, a2 := h.newAsset(res, db.AssetReady), h.newAsset(res, db.AssetReady)
	oa := h.newAsset(otherRes, db.AssetReady)

	// An empty list is an empty array.
	empty := h.mustOK(h.do(key, "GET", "/v1/playback-events", nil), 200)
	if got := items(t, empty); len(got) != 0 || strings.Contains(string(empty.raw), `"items":null`) {
		t.Fatalf("empty = %s", empty.raw)
	}

	// One real session, so the fingerprint can be checked against the session's own hash.
	sid := str(h.mustOK(h.createSession(key, a1.ID.String(), "viewer-1"), 201).m, "session_id")
	parsed, err := id.ParseSession(sid)
	if err != nil {
		t.Fatal(err)
	}
	hash := db.SessionHash(parsed)
	t0 := h.clk.Now().Add(-time.Hour)
	h.seedEvent(res, a1, hash, "", db.EventKeyReplay, t0, map[string]int64{"limit": 20})
	h.seedEvent(res, a1, hash, "", db.EventKeyRate, t0.Add(time.Minute), map[string]int64{"limit": 30})
	h.seedEvent(res, a2, nil, "viewer-2", db.EventRapidSessionCreation, t0.Add(2*time.Minute), map[string]int64{"limit": 10, "sessions": 11})
	h.seedEvent(res, a2, nil, "viewer-2", db.EventSessionLimit, t0.Add(3*time.Minute), nil)
	h.seedEvent(otherRes, oa, nil, "viewer-2", db.EventSessionLimit, t0.Add(4*time.Minute), nil) // another tenant

	all := h.mustOK(h.do(key, "GET", "/v1/playback-events", nil), 200)
	got := items(t, all)
	if want := []string{db.EventSessionLimit, db.EventRapidSessionCreation, db.EventKeyRate, db.EventKeyReplay}; !reflect.DeepEqual(kinds(got), want) {
		t.Fatalf("kinds = %v, want %v (newest first, own tenant only): %s", kinds(got), want, all.raw)
	}
	if _, ok := all.m["next_cursor"]; ok {
		t.Fatalf("a last page has a cursor: %s", all.raw)
	}
	if all.hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", all.hdr.Get("Cache-Control"))
	}
	fp := db.SessionFingerprint(hash, res.Tenant.ID)
	for _, it := range got {
		switch it["kind"] {
		case db.EventKeyReplay, db.EventKeyRate:
			if it["session"] != fp || it["viewer_id"] != "viewer-1" || it["asset_id"] != a1.ID.String() {
				t.Fatalf("session event = %v (fingerprint %s)", it, fp)
			}
		default:
			if _, has := it["session"]; has || it["viewer_id"] != "viewer-2" || it["asset_id"] != a2.ID.String() {
				t.Fatalf("viewer event = %v", it)
			}
		}
		if _, ok := it["id"].(string); !ok {
			t.Fatalf("event without id: %v", it)
		}
	}
	if got[1]["detail"].(map[string]any)["sessions"] != 11.0 {
		t.Fatalf("detail = %v", got[1]["detail"])
	}
	if got[0]["detail"] == nil {
		t.Fatalf("an event without detail has no detail object: %v", got[0])
	}
	// Nothing in the response can be turned into the session: no ID, no hash.
	for name, secret := range map[string]string{"session ID": sid, "session ID body": sid[4:], "session hash": hex.EncodeToString(hash)} {
		if strings.Contains(string(all.raw), secret) {
			t.Errorf("the response contains the %s", name)
		}
	}

	// Filters.
	q := func(params string, want ...string) resp {
		t.Helper()
		r := h.mustOK(h.do(key, "GET", "/v1/playback-events?"+params, nil), 200)
		if g := kinds(items(t, r)); !reflect.DeepEqual(g, append([]string{}, want...)) {
			t.Fatalf("?%s: kinds = %v, want %v", params, g, want)
		}
		return r
	}
	q("kind=key_rate", db.EventKeyRate)
	q("kind=segments_without_key")
	q("asset_id="+a2.ID.String(), db.EventSessionLimit, db.EventRapidSessionCreation)
	q("asset_id=" + oa.ID.String()) // another tenant's asset: nothing, not an error
	q("viewer_id=viewer-1", db.EventKeyRate, db.EventKeyReplay)
	q("viewer_id=viewer-2&kind=session_limit", db.EventSessionLimit)
	q("from="+url.QueryEscape(t0.Add(2*time.Minute).Format(time.RFC3339Nano)), db.EventSessionLimit, db.EventRapidSessionCreation)
	q("to="+url.QueryEscape(t0.Add(time.Minute).Format(time.RFC3339Nano)), db.EventKeyReplay)
	q("from="+url.QueryEscape(t0.Add(time.Minute).Format(time.RFC3339Nano))+"&to="+url.QueryEscape(t0.Add(3*time.Minute).Format(time.RFC3339Nano)),
		db.EventRapidSessionCreation, db.EventKeyRate)

	// Pagination: pages of 3 then 1, newest first, no row twice.
	first := h.mustOK(h.do(key, "GET", "/v1/playback-events?limit=3", nil), 200)
	cursor, _ := first.m["next_cursor"].(string)
	if len(items(t, first)) != 3 || cursor == "" {
		t.Fatalf("first page = %s", first.raw)
	}
	second := h.mustOK(h.do(key, "GET", "/v1/playback-events?limit=3&cursor="+url.QueryEscape(cursor), nil), 200)
	if g := kinds(items(t, second)); !reflect.DeepEqual(g, []string{db.EventKeyReplay}) {
		t.Fatalf("second page = %v", g)
	}
	if _, ok := second.m["next_cursor"]; ok {
		t.Fatal("the last page has a cursor")
	}
	// A page of 500 is the largest.
	h.mustOK(h.do(key, "GET", "/v1/playback-events?limit=500", nil), 200)

	// Tenant isolation, both ways.
	other := h.mustOK(h.do(otherKey, "GET", "/v1/playback-events", nil), 200)
	if g := kinds(items(t, other)); !reflect.DeepEqual(g, []string{db.EventSessionLimit}) {
		t.Fatalf("the other tenant sees %v", g)
	}
	if strings.Contains(string(other.raw), a1.ID.String()) || strings.Contains(string(other.raw), fp) {
		t.Fatalf("the other tenant sees acme's data: %s", other.raw)
	}
}

func TestPlaybackEventsRejectBadParameters(t *testing.T) {
	h := newHarness(t)
	key, _ := h.bootstrap("acme")
	for _, c := range []struct {
		name, query, field string
	}{
		{"limit zero", "limit=0", "limit"},
		{"limit too large", "limit=501", "limit"},
		{"limit negative", "limit=-1", "limit"},
		{"unknown kind", "kind=nope", "kind"},
		{"bad asset id", "asset_id=not-an-asset", "asset_id"},
		{"bad cursor", "cursor=garbage", "cursor"},
		{"from after to", "from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z", "from"},
		{"from equals to", "from=2026-01-01T00:00:00Z&to=2026-01-01T00:00:00Z", "from"},
		{"bad time", "from=yesterday", "from"},
		{"viewer too long", "viewer_id=" + strings.Repeat("v", 129), "viewer_id"},
	} {
		r := h.do(key, "GET", "/v1/playback-events?"+c.query, nil)
		h.wantStatus(r, 400, "invalid_request")
		if c.name != "bad time" && c.name != "limit negative" && !strings.Contains(string(r.raw), c.field) {
			t.Errorf("%s: the problem does not name %q: %s", c.name, c.field, r.raw)
		}
	}
}

func TestPlaybackEventsNeedTheAssetsReadScope(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.bootstrap("acme")
	cli := h.newClient(admin, "svc")
	for name, scopes := range map[string][]string{
		"sessions":  {"sessions:write"},
		"assets w":  {"assets:write"},
		"admin":     {"admin"}, // admin is not a superset: reading events needs assets:read
		"webhooks":  {"webhooks:manage"},
		"no assets": {"sessions:write", "webhooks:manage"},
	} {
		k := str(h.newKey(admin, cli, name, scopes).m, "key")
		h.wantStatus(h.do(k, "GET", "/v1/playback-events", nil), 403, "forbidden")
	}
	h.wantStatus(h.do("", "GET", "/v1/playback-events", nil), 401, "unauthenticated")
	reader := str(h.newKey(admin, cli, "reader", []string{"assets:read"}).m, "key")
	h.mustOK(h.do(reader, "GET", "/v1/playback-events", nil), 200)
}

// A refused creation through the API raises session_limit, readable through the events endpoint.
func TestSessionLimitThroughTheAPIIsReadable(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	h.setSettings(res, func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 1 })
	h.mustOK(h.createSession(key, asset.ID.String(), "viewer-1"), 201)
	for range 3 {
		h.wantStatus(h.createSession(key, asset.ID.String(), "viewer-1"), 409, "session_limit")
	}
	r := h.mustOK(h.do(key, "GET", "/v1/playback-events?kind=session_limit", nil), 200)
	got := items(t, r)
	if len(got) != 1 || got[0]["viewer_id"] != "viewer-1" || got[0]["asset_id"] != asset.ID.String() {
		t.Fatalf("events = %s", r.raw)
	}
	// Reading events never writes anything: no audit row, no change.
	var n int
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM playback_events").Scan(&n); err != nil || n != 1 {
		t.Fatalf("events stored = %d, %v", n, err)
	}
}
