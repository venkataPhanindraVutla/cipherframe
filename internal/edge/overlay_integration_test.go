//go:build integration

package edge_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/overlay"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth/viewerauthtest"
)

// The browser paths (JWT and callback) return the overlay like the API-key path does, built from
// the tenant's settings, and nothing in it is about the viewer.
func TestBrowserSessionsCarryTheOverlay(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	k := viewerauthtest.NewKey(t, "EdDSA", "key-overlay")
	e.enableJWT("")
	e.uploadKey(k)
	srv := e.tlsServer(&recorder{h: answer(200, allowAnswer)})
	e.rotate()
	e.enableCallback(srv.URL + "/authorize-test-fixture")

	// Off by default.
	for name, r := range map[string]reply{"jwt": e.viaJWT(k.Sign(t, e.claims("viewer-ovl"))), "callback": e.viaCallback(vTicket)} {
		if m := decode(t, r); r.status != 201 || m["overlay"] != nil {
			t.Fatalf("%s while off: %d %s", name, r.status, r.body)
		}
	}

	if _, err := e.repos.PutOverlaySettings(ctx, e.res.Tenant.ID, db.OverlaySettings{
		Enabled: true, Template: "{session_code} {date} {time}", Opacity: 0.2, FontSizeFraction: 0.05, Color: "#00FF00",
	}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]reply{"jwt": e.viaJWT(k.Sign(t, e.claims("viewer-ovl"))), "callback": e.viaCallback(vTicket)} {
		s := e.wantCreated(r)
		m := decode(t, r)
		ov, _ := m["overlay"].(map[string]any)
		if ov == nil {
			t.Fatalf("%s: no overlay: %s", name, r.body)
		}
		code, _ := ov["session_code"].(string)
		drift, _ := ov["drift"].(map[string]any)
		sid, err := parseSession(s.id)
		if err != nil {
			t.Fatal(err)
		}
		if !overlay.ValidCode(code) || ov["template"] != code+" {date} {time}" || drift["seed"] != overlay.Seed(sid) || drift["algorithm"] != "lissajous-v1" {
			t.Fatalf("%s: overlay = %v", name, ov)
		}
		raw, _ := json.Marshal(ov)
		for _, secret := range []string{"viewer-ovl", "viewer-cb", s.id, strings.TrimPrefix(s.id, "ses_"), s.token, e.asset.ID.String()} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("%s: the overlay contains %q", name, secret)
			}
		}
		// The code leads back to this session and its viewer.
		got, err := e.repos.FindSessionsByOverlayCode(ctx, e.res.Tenant.ID, code)
		if err != nil || len(got) != 1 || got[0].AssetID != e.asset.ID || !strings.HasPrefix(got[0].ViewerID, "viewer-") {
			t.Fatalf("%s: lookup = %+v, %v", name, got, err)
		}
	}
}
