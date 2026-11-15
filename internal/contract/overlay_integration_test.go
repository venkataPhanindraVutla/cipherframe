//go:build integration

package contract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/overlay"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
)

// TestOverlayOperationsMatchSpec exercises the overlay settings, the code lookup and the overlay
// member of the API-key session response through the real handler chain, validating every
// exchange against the spec. The browser paths on the edge are in internal/edge.
func TestOverlayOperationsMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	pool := dbtest.NewMigrated(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	repos := db.New(pool)
	mgr := auth.NewManager(pool, onePepper{}, nil)
	keyring, err := token.NewKeyring(map[int][]byte{1: []byte("test-fixture-playback-token-key-0123456789")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := playback.NewService(playback.Deps{Pool: pool, Keyring: keyring, EdgeURL: "https://media.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	a := api.New(api.Deps{Log: log, Verifier: auth.NewVerifier(repos, onePepper{}, log, nil), Manager: mgr, Playback: pb})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)

	ctx := context.Background()
	res, err := mgr.Bootstrap(ctx, "overlay", "overlay client")
	if err != nil {
		t.Fatal(err)
	}
	admin := map[string]string{"Authorization": "Bearer " + res.Secret.Reveal()}
	res2, err := mgr.Bootstrap(ctx, "overlay-other", "other client")
	if err != nil {
		t.Fatal(err)
	}
	other := map[string]string{"Authorization": "Bearer " + res2.Secret.Reveal()}
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
		var m map[string]any
		_ = json.Unmarshal(ex.body, &m)
		return m
	}

	cli, err := mgr.CreateClient(ctx, res.Tenant.ID, auth.Actor{}, "reader")
	if err != nil {
		t.Fatal(err)
	}
	rk, err := mgr.CreateKey(ctx, res.Tenant.ID, auth.Actor{}, auth.CreateKeyInput{ClientID: cli.ID, Name: "reader", Scopes: []db.Scope{db.ScopeAssetsRead}})
	if err != nil {
		t.Fatal(err)
	}
	reader := map[string]string{"Authorization": "Bearer " + rk.Secret.Reveal()}

	asset := readyAsset(t, repos, res, db.AssetReady)
	asset2 := readyAsset(t, repos, res2, db.AssetReady)
	const viewer = "viewer-overlay-7f3a"
	newSession := func(hdr map[string]string, assetID, viewerID string) map[string]any {
		return call(hdr, "POST", "/v1/playback-sessions", map[string]any{"asset_id": assetID, "viewer_id": viewerID}, 201)
	}

	// Off by default: the defaults apply and a session carries no overlay.
	def := call(admin, "GET", "/v1/overlay-settings", nil, 200)
	if _, has := def["updated_at"]; has || def["enabled"] != false || def["template"] != "{session_code} {date} {time} UTC" {
		t.Fatalf("default settings = %v", def)
	}
	if s := newSession(admin, asset.ID.String(), viewer); s["overlay"] != nil {
		t.Fatalf("overlay while off: %v", s["overlay"])
	}

	// Hostile or malformed settings are refused field by field and store nothing.
	full := func(edit func(map[string]any)) map[string]any {
		m := map[string]any{"enabled": true, "template": "ID {session_code} {date} {time}", "opacity": 0.3, "font_size_fraction": 0.04, "color": "#FFCC00"}
		if edit != nil {
			edit(m)
		}
		return m
	}
	for name, edit := range map[string]func(map[string]any){
		"unknown placeholder": func(m map[string]any) { m["template"] = "{viewer_id} {date}" },
		"email placeholder":   func(m map[string]any) { m["template"] = "{email} {session_code}" },
		"markup":              func(m map[string]any) { m["template"] = "<img src=x onerror=alert(1)>{date}" },
		"line break":          func(m map[string]any) { m["template"] = "{date}\n{time}" },
		"control":             func(m map[string]any) { m["template"] = "{date}\u0000" },
		"no placeholder":      func(m map[string]any) { m["template"] = "Confidential" },
		"too long":            func(m map[string]any) { m["template"] = strings.Repeat("x", 120) + "{date}" },
		"stray brace":         func(m map[string]any) { m["template"] = "{date} {" },
		"opacity":             func(m map[string]any) { m["opacity"] = 1.0 },
		"size":                func(m map[string]any) { m["font_size_fraction"] = 0.001 },
		"color":               func(m map[string]any) { m["color"] = "yellow" },
	} {
		p := call(admin, "PUT", "/v1/overlay-settings", full(edit), 400)
		if p["code"] != "invalid_request" || p["errors"] == nil {
			t.Fatalf("%s: problem = %v", name, p)
		}
	}
	call(admin, "PUT", "/v1/overlay-settings", map[string]any{"enabled": true}, 400) // incomplete
	if got := call(admin, "GET", "/v1/overlay-settings", nil, 200); got["enabled"] != false {
		t.Fatalf("a refused PUT stored something: %v", got)
	}

	// Scopes and tenants.
	call(reader, "GET", "/v1/overlay-settings", nil, 403)
	call(reader, "PUT", "/v1/overlay-settings", full(nil), 403)
	call(nil, "GET", "/v1/overlay-settings", nil, 401)
	put := call(admin, "PUT", "/v1/overlay-settings", full(nil), 200)
	if _, has := put["updated_at"]; !has || put["enabled"] != true || put["color"] != "#FFCC00" {
		t.Fatalf("replaced settings = %v", put)
	}
	if got := call(other, "GET", "/v1/overlay-settings", nil, 200); got["enabled"] != false {
		t.Fatalf("another tenant sees the settings: %v", got)
	}

	// Every session now carries the overlay, with nothing about the viewer in it.
	created := newSession(admin, asset.ID.String(), viewer)
	ov, _ := created["overlay"].(map[string]any)
	if ov == nil {
		t.Fatalf("no overlay: %v", created)
	}
	code, _ := ov["session_code"].(string)
	if !overlay.ValidCode(code) || ov["template"] != "ID "+code+" {date} {time}" {
		t.Fatalf("overlay = %v", ov)
	}
	style, _ := ov["style"].(map[string]any)
	drift, _ := ov["drift"].(map[string]any)
	if style["opacity"] != 0.3 || style["font_size_fraction"] != 0.04 || style["color"] != "#FFCC00" ||
		drift["algorithm"] != "lissajous-v1" || drift["period_seconds"] != float64(overlay.PeriodSeconds) || drift["margin"] != overlay.Margin {
		t.Fatalf("style %v drift %v", style, drift)
	}
	sidText, _ := created["session_id"].(string)
	seed, _ := drift["seed"].(string)
	raw, _ := json.Marshal(ov)
	for name, secret := range map[string]string{
		"viewer ID": viewer, "session ID": sidText, "token": created["token"].(string), "asset ID": asset.ID.String(),
		"tenant ID": res.Tenant.ID.String(), "session ID body": strings.TrimPrefix(sidText, "ses_"),
	} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the overlay contains the %s: %s", name, raw)
		}
	}
	// The seed is the one-way derivation of this session, so the same session always gets the same path.
	sid, err := id.ParseSession(sidText)
	if err != nil || seed != overlay.Seed(sid) || strings.Contains(sidText, seed) {
		t.Fatalf("seed %q for session: %v", seed, err)
	}
	second := newSession(admin, asset.ID.String(), viewer)
	ov2, _ := second["overlay"].(map[string]any)
	if ov2["session_code"] == code || ov2["drift"].(map[string]any)["seed"] == seed {
		t.Fatalf("two sessions share a code or a path: %v %v", ov, ov2)
	}

	// The code maps back to the session and viewer, through the tenant's own data only.
	lookup := call(admin, "GET", "/v1/overlay-codes/"+code, nil, 200)
	sessions, _ := lookup["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("lookup = %v", lookup)
	}
	m, _ := sessions[0].(map[string]any)
	tu := res.Tenant.ID.UUID()
	h := sha256.Sum256(append(db.SessionHash(sid), tu[:]...))
	if m["viewer_id"] != viewer || m["asset_id"] != asset.ID.String() || m["auth_method"] != "api_key" || m["state"] != "active" ||
		m["session_fingerprint"] != hex.EncodeToString(h[:4]) {
		t.Fatalf("matched session = %v", m)
	}
	if got := call(admin, "GET", "/v1/overlay-codes/"+strings.ToLower(code), nil, 200); len(got["sessions"].([]any)) != 1 {
		t.Fatalf("lookup is case-sensitive: %v", got)
	}
	call(reader, "GET", "/v1/overlay-codes/"+code, nil, 200) // assets:read, like the access trail
	call(nil, "GET", "/v1/overlay-codes/"+code, nil, 401)
	if got := call(other, "GET", "/v1/overlay-codes/"+code, nil, 200); len(got["sessions"].([]any)) != 0 {
		t.Fatalf("another tenant resolved the code: %v", got)
	}
	if got := call(admin, "GET", "/v1/overlay-codes/AAAAAAAA", nil, 200); len(got["sessions"].([]any)) != 0 {
		t.Fatalf("unknown code = %v", got)
	}
	for _, bad := range []string{"ABCDEFG0", "ABCDEFGI", "abc-defg", "ABCDEFGHJKLMNPQR"} {
		call(admin, "GET", "/v1/overlay-codes/"+bad, nil, 400)
	}
	// The other tenant's sessions get their own overlay only once it enabled its own.
	if s := newSession(other, asset2.ID.String(), viewer); s["overlay"] != nil {
		t.Fatalf("the overlay leaked to another tenant: %v", s["overlay"])
	}

	// Past the retention window the code no longer leads anywhere.
	if n, err := repos.ClearOverlayCodesBefore(ctx, time.Now().Add(time.Hour), 100); err != nil || n < 2 {
		t.Fatalf("cleared %d, %v", n, err)
	}
	if got := call(admin, "GET", "/v1/overlay-codes/"+code, nil, 200); len(got["sessions"].([]any)) != 0 {
		t.Fatalf("a cleared code resolved: %v", got)
	}

	// Turning it off again removes the member from later sessions.
	call(admin, "PUT", "/v1/overlay-settings", full(func(m map[string]any) { m["enabled"] = false }), 200)
	if s := newSession(admin, asset.ID.String(), "viewer-after"); s["overlay"] != nil {
		t.Fatalf("overlay after disabling: %v", s["overlay"])
	}

	for _, op := range []string{"getOverlaySettings", "updateOverlaySettings", "lookupOverlayCode", "createPlaybackSession"} {
		if !covered[op] {
			t.Fatalf("%s was not exercised with a 2xx response; covered = %v", op, covered)
		}
	}
}
