//go:build integration

package contract

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

// The tenant's extra_codecs setting is copied onto the asset when it is created (ADR 0064): a later
// change reaches new uploads only, and the asset reports what it asked for.
func TestAssetExtraCodecsSnapshot(t *testing.T) {
	e := newUpEnv(t)
	ctx := context.Background()
	body := map[string]any{"size_bytes": 100, "upload_method": "multipart"}
	setCodecs := func(codecs ...string) {
		t.Helper()
		s := db.DefaultPlaybackSettings()
		s.ExtraCodecs = codecs
		if _, err := e.repos.PutPlaybackSettings(ctx, e.tenant.ID, s, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	asset := func(m map[string]any) map[string]any { return m["asset"].(map[string]any) }

	// The default is H.264 only, and the asset says nothing about codecs.
	m, _ := e.call(e.admin, "POST", "/v1/assets", body, 201)
	if _, has := asset(m)["extra_codecs"]; has {
		t.Fatalf("an asset created with the setting empty has extra_codecs: %v", asset(m))
	}

	setCodecs("hevc", "av1")
	m, _ = e.call(e.admin, "POST", "/v1/assets", body, 201)
	first := asset(m)["id"].(string)
	want := map[string]any{"requested": []any{"hevc", "av1"}, "failed": []any{}}
	if got := asset(m)["extra_codecs"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("extra_codecs = %v, want %v", got, want)
	}
	if got := e.dbAsset(first).ExtraCodecs; !reflect.DeepEqual(got, []string{"hevc", "av1"}) {
		t.Fatalf("stored extra_codecs = %v", got)
	}

	// Changing the setting does not touch the asset that exists; a new one gets the new value.
	setCodecs("av1")
	got, _ := e.call(e.admin, "GET", "/v1/assets/"+first, nil, 200)
	if !reflect.DeepEqual(got["extra_codecs"], want) {
		t.Fatalf("after the setting changed: %v", got["extra_codecs"])
	}
	m, _ = e.call(e.admin, "POST", "/v1/assets", body, 201)
	if got := asset(m)["extra_codecs"]; !reflect.DeepEqual(got, map[string]any{"requested": []any{"av1"}, "failed": []any{}}) {
		t.Fatalf("new asset: %v", got)
	}
}
