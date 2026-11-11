//go:build integration

package api_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
)

func sessionPath(sid string) string { return "/v1/playback-sessions/" + sid }

func (h *harness) rowOf(res auth.BootstrapResult, sid string) db.PlaybackSession {
	h.t.Helper()
	parsed, err := id.ParseSession(sid)
	if err != nil {
		h.t.Fatal(err)
	}
	row, err := h.repos.GetPlaybackSession(context.Background(), res.Tenant.ID, db.SessionHash(parsed))
	if err != nil {
		h.t.Fatal(err)
	}
	return row
}

func (h *harness) auditActions(res auth.BootstrapResult) []db.AuditEvent {
	h.t.Helper()
	events, err := h.repos.ListAuditEvents(context.Background(), res.Tenant.ID, nil, 100)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []db.AuditEvent
	for _, ev := range events {
		if strings.HasPrefix(ev.Action, "playback_session") {
			out = append(out, ev)
		}
	}
	return out
}

func TestGetPlaybackSessionStatus(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	created := h.mustOK(h.createSession(key, asset.ID.String(), "viewer-1"), 201)
	sid, tok := str(created.m, "session_id"), str(created.m, "token")

	r := h.mustOK(h.do(key, "GET", sessionPath(sid), nil), 200)
	if r.m["state"] != "active" || str(r.m, "session_id") != sid || str(r.m, "asset_id") != asset.ID.String() || str(r.m, "viewer_id") != "viewer-1" {
		t.Fatalf("status = %s", r.raw)
	}
	for _, k := range []string{"ended_at", "revoked_at", "revoke_reason"} {
		if _, ok := r.m[k]; ok {
			t.Fatalf("%s is present on an active session: %s", k, r.raw)
		}
	}
	if strings.Contains(string(r.raw), tok) || strings.Contains(string(r.raw), "token") {
		t.Fatalf("the status carries a token: %s", r.raw)
	}

	// Idle past the timeout (default 5 minutes): ended by computation, though the row says active.
	h.clk.Advance(301 * time.Second)
	r = h.mustOK(h.do(key, "GET", sessionPath(sid), nil), 200)
	if r.m["state"] != "ended" {
		t.Fatalf("idle session state = %v", r.m["state"])
	}
	if h.rowOf(res, sid).State != db.PlaybackActive {
		t.Fatal("reading the status changed the row")
	}
	if _, ok := r.m["ended_at"]; ok {
		t.Fatalf("computed ended carries ended_at: %s", r.raw)
	}

	// Past the maximum age with a fresh heartbeat: also ended.
	h.setSettings(res, func(s *db.PlaybackSettings) { s.SessionMaxSeconds = 300; s.IdleTimeoutSeconds = 3600 })
	h.clk.Advance(-301 * time.Second)
	fresh := h.mustOK(h.createSession(key, asset.ID.String(), "viewer-2"), 201)
	h.clk.Advance(301 * time.Second)
	if got := h.mustOK(h.do(key, "GET", sessionPath(str(fresh.m, "session_id")), nil), 200); got.m["state"] != "ended" {
		t.Fatalf("expired session state = %v", got.m["state"])
	}

	// A made-up, a malformed and another tenant's session are the same 404.
	otherKey, _ := h.bootstrap("other")
	made, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{made.String(), "ses_nope", "x"}
	var details []any
	for _, s := range ids {
		r := h.do(key, "GET", sessionPath(s), nil)
		h.wantStatus(r, 404, "not_found")
		details = append(details, r.m["detail"])
	}
	cross := h.do(otherKey, "GET", sessionPath(sid), nil)
	h.wantStatus(cross, 404, "not_found")
	details = append(details, cross.m["detail"])
	for _, d := range details {
		if d != details[0] {
			t.Fatalf("details differ: %v", details)
		}
	}
}

func TestRevokePlaybackSession(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	otherKey, otherRes := h.bootstrap("other")
	asset := h.newAsset(res, db.AssetReady)
	created := h.mustOK(h.createSession(key, asset.ID.String(), "viewer-1"), 201)
	sid, tok := str(created.m, "session_id"), str(created.m, "token")

	// Another tenant cannot see or revoke it: 404, and nothing changes.
	h.wantStatus(h.do(otherKey, "POST", sessionPath(sid)+"/revoke", map[string]any{"reason": "nope"}), 404, "not_found")
	if h.rowOf(res, sid).State != db.PlaybackActive {
		t.Fatal("another tenant revoked the session")
	}
	_ = otherRes

	r := h.mustOK(h.do(key, "POST", sessionPath(sid)+"/revoke", map[string]any{"reason": "chargeback"}), 200)
	if r.m["state"] != "revoked" || r.m["revoke_reason"] != "chargeback" || str(r.m, "revoked_at") == "" {
		t.Fatalf("revoke = %s", r.raw)
	}
	if strings.Contains(string(r.raw), tok) {
		t.Fatal("the revoke response carries the token")
	}
	row := h.rowOf(res, sid)
	if row.State != db.PlaybackRevoked || row.RevokeReason != "chargeback" || row.RevokedAt == nil {
		t.Fatalf("row = %+v", row)
	}
	if got := h.mustOK(h.do(key, "GET", sessionPath(sid), nil), 200); got.m["state"] != "revoked" || got.m["revoke_reason"] != "chargeback" {
		t.Fatalf("status = %s", got.raw)
	}

	// Idempotent: the second call is a 200, keeps the first reason and time, and adds no audit event.
	h.clk.Advance(time.Minute)
	again := h.mustOK(h.do(key, "POST", sessionPath(sid)+"/revoke", map[string]any{"reason": "second"}), 200)
	if again.m["state"] != "revoked" || again.m["revoke_reason"] != "chargeback" || again.m["revoked_at"] != r.m["revoked_at"] {
		t.Fatalf("second revoke = %s", again.raw)
	}
	if n := len(h.auditActions(res)); n != 1 {
		t.Fatalf("audit events = %d, want 1", n)
	}
	ev := h.auditActions(res)[0]
	if ev.Action != playback.AuditSessionRevoke || strings.Contains(ev.Target, sid) || strings.Contains(ev.Target, sid[4:]) || ev.Target == "" {
		t.Fatalf("audit event = %+v", ev)
	}
	if ev.ClientID != res.Client.ID {
		t.Fatalf("audit actor = %+v", ev)
	}
}

func TestRevokePlaybackSessionBodyIsOptionalAndValidated(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	mk := func(v string) string {
		return str(h.mustOK(h.createSession(key, asset.ID.String(), v), 201).m, "session_id")
	}

	sid := mk("a")
	r := h.mustOK(h.do(key, "POST", sessionPath(sid)+"/revoke", nil), 200)
	if r.m["state"] != "revoked" {
		t.Fatalf("revoke = %s", r.raw)
	}
	if _, ok := r.m["revoke_reason"]; ok {
		t.Fatalf("a reason appeared from nowhere: %s", r.raw)
	}

	sid = mk("b")
	for name, reason := range map[string]string{
		"too long": strings.Repeat("x", 201), "control": "a\x00b", "newline": "a\nb",
	} {
		h.wantStatus(h.do(key, "POST", sessionPath(sid)+"/revoke", map[string]any{"reason": reason}), 400, "invalid_request")
		if h.rowOf(res, sid).State != db.PlaybackActive {
			t.Fatalf("%s: a rejected request revoked the session", name)
		}
	}
	h.mustOK(h.do(key, "POST", sessionPath(sid)+"/revoke", map[string]any{"reason": strings.Repeat("é", 200)}), 200)
}

// Revoking an ended session succeeds and leaves it ended: the record keeps how it really finished.
func TestRevokeEndedSessionLeavesItEnded(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	sid := str(h.mustOK(h.createSession(key, asset.ID.String(), "v"), 201).m, "session_id")
	if _, err := h.pool.Exec(context.Background(),
		"UPDATE playback_sessions SET state = 'ended', ended_at = $1 WHERE tenant_id = $2", h.clk.Now(), res.Tenant.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	r := h.mustOK(h.do(key, "POST", sessionPath(sid)+"/revoke", map[string]any{"reason": "late"}), 200)
	if r.m["state"] != "ended" {
		t.Fatalf("revoke of an ended session = %s", r.raw)
	}
	if _, ok := r.m["revoked_at"]; ok {
		t.Fatalf("an ended session got revoked_at: %s", r.raw)
	}
	if n := len(h.auditActions(res)); n != 0 {
		t.Fatalf("audit events = %d, want 0", n)
	}
}

func TestRevokePlaybackSessionsBulk(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	otherKey, otherRes := h.bootstrap("other")
	a1, a2 := h.newAsset(res, db.AssetReady), h.newAsset(res, db.AssetReady)
	foreign := h.newAsset(otherRes, db.AssetReady)
	h.setSettings(res, func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 0 })

	mk := func(k, asset, viewer string) string {
		return str(h.mustOK(h.createSession(k, asset, viewer), 201).m, "session_id")
	}
	v1a1, v1a1b, v1a2 := mk(key, a1.ID.String(), "v1"), mk(key, a1.ID.String(), "v1"), mk(key, a2.ID.String(), "v1")
	v2a1, v2a2 := mk(key, a1.ID.String(), "v2"), mk(key, a2.ID.String(), "v2")
	// The same viewer ID in another tenant.
	otherSess := mk(otherKey, foreign.ID.String(), "v1")
	state := func(k, sid string) any { return h.mustOK(h.do(k, "GET", sessionPath(sid), nil), 200).m["state"] }

	// A filter is required.
	for name, body := range map[string]any{
		"empty": map[string]any{}, "reason only": map[string]any{"reason": "x"},
		"empty viewer": map[string]any{"viewer_id": ""}, "bad asset": map[string]any{"asset_id": "nope"},
	} {
		h.wantStatus(h.do(key, "POST", "/v1/playback-sessions/revoke", body), 400, "invalid_request")
		_ = name
	}
	h.wantStatus(h.do(key, "POST", "/v1/playback-sessions/revoke", nil), 400, "invalid_request")
	if n := len(h.auditActions(res)); n != 0 {
		t.Fatalf("a rejected request was audited (%d)", n)
	}

	// By viewer: all of v1's sessions in this tenant, nothing else, nothing in the other tenant.
	r := h.mustOK(h.do(key, "POST", "/v1/playback-sessions/revoke", map[string]any{"viewer_id": "v1", "reason": "fraud"}), 200)
	if r.m["revoked"] != float64(3) {
		t.Fatalf("revoked = %s", r.raw)
	}
	for _, s := range []string{v1a1, v1a1b, v1a2} {
		if state(key, s) != "revoked" {
			t.Fatalf("a v1 session is %v", state(key, s))
		}
	}
	if state(key, v2a1) != "active" || state(key, v2a2) != "active" || state(otherKey, otherSess) != "active" {
		t.Fatal("a session outside the filter was revoked")
	}
	if got := h.mustOK(h.do(key, "GET", sessionPath(v1a1), nil), 200); got.m["revoke_reason"] != "fraud" {
		t.Fatalf("status = %s", got.raw)
	}
	// Repeating finds nothing left.
	if r := h.mustOK(h.do(key, "POST", "/v1/playback-sessions/revoke", map[string]any{"viewer_id": "v1"}), 200); r.m["revoked"] != float64(0) {
		t.Fatalf("repeat = %s", r.raw)
	}

	// By asset, in this tenant only; a foreign asset matches nothing.
	if r := h.mustOK(h.do(key, "POST", "/v1/playback-sessions/revoke", map[string]any{"asset_id": foreign.ID.String()}), 200); r.m["revoked"] != float64(0) {
		t.Fatalf("foreign asset = %s", r.raw)
	}
	if state(otherKey, otherSess) != "active" {
		t.Fatal("another tenant's session was revoked through its asset")
	}
	if r := h.mustOK(h.do(key, "POST", "/v1/playback-sessions/revoke", map[string]any{"asset_id": a1.ID.String()}), 200); r.m["revoked"] != float64(1) {
		t.Fatalf("by asset = %s", r.raw)
	}
	if state(key, v2a1) != "revoked" || state(key, v2a2) != "active" {
		t.Fatal("the asset filter hit the wrong sessions")
	}

	// Both filters must match.
	if r := h.mustOK(h.do(key, "POST", "/v1/playback-sessions/revoke", map[string]any{"asset_id": a1.ID.String(), "viewer_id": "v2"}), 200); r.m["revoked"] != float64(0) {
		t.Fatalf("both filters = %s", r.raw)
	}
	if r := h.mustOK(h.do(key, "POST", "/v1/playback-sessions/revoke", map[string]any{"asset_id": a2.ID.String(), "viewer_id": "v2"}), 200); r.m["revoked"] != float64(1) {
		t.Fatalf("both filters = %s", r.raw)
	}

	// Two audited bulk revokes by viewer and by asset, plus the last one; zero-count calls are not.
	evs := h.auditActions(res)
	if len(evs) != 3 {
		t.Fatalf("audit events = %+v", evs)
	}
	for _, ev := range evs {
		if ev.Action != playback.AuditSessionRevokeBulk || ev.ClientID != res.Client.ID || strings.Contains(ev.Target, "ses_") {
			t.Fatalf("audit event = %+v", ev)
		}
	}
	if evs[0].Target != "viewer=v1 revoked=3" {
		t.Fatalf("target = %q", evs[0].Target)
	}
}

func TestPlaybackSessionOperationsNeedTheSessionsScope(t *testing.T) {
	h := newHarness(t)
	admin, res := h.bootstrap("acme")
	asset := h.newAsset(res, db.AssetReady)
	sid := str(h.mustOK(h.createSession(admin, asset.ID.String(), "v"), 201).m, "session_id")
	reader := str(h.mustOK(h.newKey(admin, res.Client.ID.String(), "reader", []string{"assets:read"}), 201).m, "key")

	h.wantStatus(h.do(reader, "GET", sessionPath(sid), nil), 403, "forbidden")
	h.wantStatus(h.do(reader, "POST", sessionPath(sid)+"/revoke", nil), 403, "forbidden")
	h.wantStatus(h.do(reader, "POST", "/v1/playback-sessions/revoke", map[string]any{"viewer_id": "v"}), 403, "forbidden")
	h.wantStatus(h.do("", "GET", sessionPath(sid), nil), 401, "unauthenticated")
	if h.rowOf(res, sid).State != db.PlaybackActive {
		t.Fatal("a forbidden request revoked the session")
	}
}

// The sweep ends idle and expired sessions, in batches, and leaves everything else alone.
func TestSweepSessions(t *testing.T) {
	h := newHarness(t)
	key, res := h.bootstrap("acme")
	otherKey, otherRes := h.bootstrap("other")
	asset, foreign := h.newAsset(res, db.AssetReady), h.newAsset(otherRes, db.AssetReady)
	h.setSettings(res, func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 0; s.IdleTimeoutSeconds = 300 })
	// The other tenant has no stored settings: the default idle timeout (300 s) applies, and a
	// different one is configured to prove the join uses each tenant's own value.
	h.setSettings(otherRes, func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 0; s.IdleTimeoutSeconds = 1800 })

	mk := func(k, asset, viewer string) string {
		return str(h.mustOK(h.createSession(k, asset, viewer), 201).m, "session_id")
	}
	var idle []string
	for range 5 {
		idle = append(idle, mk(key, asset.ID.String(), "idle"))
	}
	otherIdle := mk(otherKey, foreign.ID.String(), "idle") // 1800 s timeout: not due at +400 s
	h.clk.Advance(400 * time.Second)
	active := mk(key, asset.ID.String(), "active")
	revoked := mk(key, asset.ID.String(), "revoked")
	h.mustOK(h.do(key, "POST", sessionPath(revoked)+"/revoke", nil), 200)

	// Batches of 2 over 5 due sessions: 2 + 2 + 1, all in one run.
	n, err := playback.SweepSessions(context.Background(), h.repos, h.clk.Now(), 2)
	if err != nil || n != 5 {
		t.Fatalf("swept %d, %v", n, err)
	}
	for _, s := range idle {
		row := h.rowOf(res, s)
		if row.State != db.PlaybackEnded || row.EndedAt == nil {
			t.Fatalf("idle session row = %+v", row)
		}
	}
	if h.rowOf(res, active).State != db.PlaybackActive || h.rowOf(res, revoked).State != db.PlaybackRevoked {
		t.Fatal("the sweep touched an active or revoked session")
	}
	if h.rowOf(otherRes, otherIdle).State != db.PlaybackActive {
		t.Fatal("the sweep used another tenant's idle timeout")
	}
	// Nothing left; a second run is a no-op.
	if n, err := playback.SweepSessions(context.Background(), h.repos, h.clk.Now(), 2); err != nil || n != 0 {
		t.Fatalf("second sweep = %d, %v", n, err)
	}

	// Past the maximum age with fresh heartbeats; then the tenant with the long timeout goes idle.
	h.clk.Advance(4 * time.Hour)
	if n, err := playback.SweepSessions(context.Background(), h.repos, h.clk.Now(), playback.SweepBatch); err != nil || n != 2 {
		t.Fatalf("swept %d, %v", n, err) // `active` (expired) and the other tenant's session
	}
	if h.rowOf(res, active).State != db.PlaybackEnded || h.rowOf(otherRes, otherIdle).State != db.PlaybackEnded {
		t.Fatal("expired sessions were not ended")
	}
	if strings.Contains(h.logs.String(), idle[0]) {
		t.Fatal("a session ID reached the log")
	}
}
