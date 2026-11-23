//go:build integration

package db_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"
	"uuid"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// Worker capabilities: one row per process, updated in place, read through a freshness cutoff.
func TestWorkerCapabilities(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	now := micro(time.Now())
	w1, w2 := uuid.New(), uuid.New()

	got, err := r.RecentWorkerCodecs(ctx, now.Add(-5*time.Minute))
	if err != nil || len(got) != 0 {
		t.Fatalf("no workers: %v, %v", got, err)
	}
	if err := r.UpsertWorkerCapabilities(ctx, w1, []string{"hevc"}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := r.UpsertWorkerCapabilities(ctx, w2, []string{"av1", "hevc"}, now); err != nil {
		t.Fatal(err)
	}
	cutoff := now.Add(-5 * time.Minute)
	if got, err = r.RecentWorkerCodecs(ctx, cutoff); err != nil || !slices.Equal(got, []string{"av1", "hevc"}) {
		t.Fatalf("recent: %v, %v", got, err)
	}
	// The same process beating again replaces its row.
	if err := r.UpsertWorkerCapabilities(ctx, w2, nil, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, err = r.RecentWorkerCodecs(ctx, cutoff); err != nil || len(got) != 0 {
		t.Fatalf("after w2 reports none: %v, %v", got, err)
	}
	// An unknown codec never reaches the table.
	if err := r.UpsertWorkerCapabilities(ctx, w1, []string{"vp9"}, now); err == nil {
		t.Fatal("an unknown codec was stored")
	}
	// Pruning removes the long-gone row only.
	n, err := r.PruneWorkerCapabilities(ctx, now.Add(-30*time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, %v", n, err)
	}
}

// The setting round-trips and defaults to none, matching DefaultPlaybackSettings; the table refuses an
// unknown codec.
func TestPlaybackSettingsExtraCodecs(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")

	got, err := r.GetPlaybackSettings(ctx, f.tenant.ID)
	if err != nil || len(got.ExtraCodecs) != 0 || got.ExtraCodecs == nil {
		t.Fatalf("default: %v, %v", got.ExtraCodecs, err)
	}
	in := db.DefaultPlaybackSettings()
	in.ExtraCodecs = []string{"av1", "hevc"}
	out, err := r.PutPlaybackSettings(ctx, f.tenant.ID, in, micro(time.Now()))
	if err != nil || !slices.Equal(out.ExtraCodecs, []string{"av1", "hevc"}) {
		t.Fatalf("put: %v, %v", out.ExtraCodecs, err)
	}
	if got, err = r.GetPlaybackSettings(ctx, f.tenant.ID); err != nil || !slices.Equal(got.ExtraCodecs, []string{"av1", "hevc"}) {
		t.Fatalf("get: %v, %v", got.ExtraCodecs, err)
	}
	for _, bad := range []string{"'{vp9}'", "'{hevc,av1,hevc}'"} {
		if _, err := pool.Exec(ctx, "UPDATE playback_settings SET extra_codecs = "+bad+"::text[]"); err == nil {
			t.Errorf("the table accepted %s", bad)
		}
	}
}

// An asset keeps the codecs it was created with and the failures recorded when it became ready.
func TestAssetExtraCodecsAndFailures(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")

	plain := newUploadAsset(t, r, f, db.UploadMultipart)
	if len(plain.ExtraCodecs) != 0 || len(plain.ExtraCodecFailures) != 0 {
		t.Fatalf("a plain asset: %+v", plain)
	}
	a, err := r.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: f.tenant.ID, ClientID: f.client.ID, SizeBytes: 1234, Method: db.UploadMultipart,
		SourceKey: "t/x/a/y/source/z", ExpiresAt: time.Now().Add(time.Hour).UTC(), ExtraCodecs: []string{"hevc", "av1"},
	})
	if err != nil || !slices.Equal(a.ExtraCodecs, []string{"hevc", "av1"}) {
		t.Fatalf("create: %+v, %v", a, err)
	}
	for _, step := range [][2]db.AssetState{
		{db.AssetCreated, db.AssetUploading}, {db.AssetUploading, db.AssetCommitted}, {db.AssetCommitted, db.AssetProcessing},
	} {
		if _, err := r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: step[0], To: step[1]}); err != nil {
			t.Fatal(err)
		}
	}
	summary, _ := json.Marshal([]map[string]any{{"name": "720p"}})
	done, err := r.CompleteProcessing(ctx, f.tenant.ID, a.ID, db.Completion{
		Duration: time.Second, Renditions: summary, ExtraCodecFailures: []db.CodecFailure{{Codec: "av1", Reason: db.CodecEncoderUnavailable}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []db.CodecFailure{{Codec: "av1", Reason: db.CodecEncoderUnavailable}}
	if !slices.Equal(done.ExtraCodecFailures, want) || !slices.Equal(done.ExtraCodecs, []string{"hevc", "av1"}) {
		t.Fatalf("completed: %+v", done)
	}
	if got, err := r.GetAsset(ctx, f.tenant.ID, a.ID); err != nil || !slices.Equal(got.ExtraCodecFailures, want) {
		t.Fatalf("read back: %+v, %v", got, err)
	}
}
