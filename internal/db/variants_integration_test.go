//go:build integration

package db_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

func maskingAsset(t *testing.T, r *db.Repos, f fixture) db.Asset {
	t.Helper()
	a, err := r.CreateUploadAsset(context.Background(), db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: f.tenant.ID, ClientID: f.client.ID, SizeBytes: 1234,
		Method: db.UploadMultipart, SourceKey: "t/x/a/y/source/" + id.New[id.AssetKind]().String(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(), MaskFaces: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestContentKeysAreOnePerVariantAndShreddedTogether(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := newUploadAsset(t, r, f, db.UploadTus)

	orig, err := r.CreateContentKey(ctx, f.tenant.ID, newRow(a.ID, kekV1))
	if err != nil {
		t.Fatal(err)
	}
	masked := newRow(a.ID, kekV1)
	masked.Variant = keys.Masked
	mrow, err := r.CreateContentKey(ctx, f.tenant.ID, masked)
	if err != nil {
		t.Fatalf("a masked key next to the original: %v", err)
	}
	if mrow.ID == orig.ID || mrow.Variant != keys.Masked || orig.Variant != keys.Original {
		t.Fatalf("variants mixed up: %+v %+v", orig, mrow)
	}
	// A second key of the same variant still conflicts.
	again := newRow(a.ID, kekV1)
	again.Variant = keys.Masked
	_, err = r.CreateContentKey(ctx, f.tenant.ID, again)
	wantCode(t, err, errs.Conflict)

	for v, want := range map[keys.Variant]id.ContentKeyID{keys.Original: orig.ID, keys.Masked: mrow.ID} {
		got, err := r.GetContentKey(ctx, f.tenant.ID, a.ID, v)
		if err != nil || got.ID != want {
			t.Fatalf("GetContentKey(%s) = %+v, %v", v, got, err)
		}
	}
	// An unknown variant never reaches the database.
	bad := newRow(a.ID, kekV1)
	bad.Variant = "other"
	_, err = r.CreateContentKey(ctx, f.tenant.ID, bad)
	wantCode(t, err, errs.InvalidRequest)

	// Crypto-shredding deletes every variant.
	n, err := r.DeleteContentKey(ctx, f.tenant.ID, a.ID)
	if err != nil || n != 2 {
		t.Fatalf("DeleteContentKey = %d, %v; want 2", n, err)
	}
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		_, err = r.GetContentKey(ctx, f.tenant.ID, a.ID, v)
		wantCode(t, err, errs.NotFound)
	}
}

func TestMaskingStateOfAnAsset(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")

	plain := newUploadAsset(t, r, f, db.UploadMultipart)
	if plain.MaskFaces || plain.MaskingState != "" || plain.FacesDetected != nil {
		t.Fatalf("a default asset has masking: %+v", plain)
	}
	_, err := r.SetAssetMasking(ctx, f.tenant.ID, plain.ID, db.MaskingReady, nil, time.Time{})
	wantCode(t, err, errs.NotFound) // only an asset created with mask_faces

	a := maskingAsset(t, r, f)
	if !a.MaskFaces || a.MaskingState != "" {
		t.Fatalf("new masking asset: %+v", a)
	}
	for _, step := range [][2]db.AssetState{
		{db.AssetCreated, db.AssetUploading}, {db.AssetUploading, db.AssetCommitted}, {db.AssetCommitted, db.AssetProcessing},
	} {
		if a, err = r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: step[0], To: step[1]}); err != nil {
			t.Fatal(err)
		}
	}
	// Completing the original makes the masked variant pending, in the same statement.
	a, err = r.CompleteProcessing(ctx, f.tenant.ID, a.ID, db.Completion{Duration: time.Second, Renditions: json.RawMessage(`[]`)})
	if err != nil || a.State != db.AssetReady || a.MaskingState != db.MaskingPending {
		t.Fatalf("after completion: %+v, %v", a, err)
	}

	faces := 3
	a, err = r.SetAssetMasking(ctx, f.tenant.ID, a.ID, db.MaskingReady, &faces, time.Time{})
	if err != nil || a.MaskingState != db.MaskingReady || a.FacesDetected == nil || *a.FacesDetected != 3 {
		t.Fatalf("SetAssetMasking: %+v, %v", a, err)
	}
	neg := -1
	_, err = r.SetAssetMasking(ctx, f.tenant.ID, a.ID, db.MaskingReady, &neg, time.Time{})
	wantCode(t, err, errs.InvalidRequest)
	_, err = r.SetAssetMasking(ctx, f.tenant.ID, a.ID, "done", nil, time.Time{})
	wantCode(t, err, errs.InvalidRequest)

	// A plain asset completes without a masking state.
	p := processingAsset(t, r, f)
	p, err = r.CompleteProcessing(ctx, f.tenant.ID, p.ID, db.Completion{Duration: time.Second, Renditions: json.RawMessage(`[]`)})
	if err != nil || p.MaskingState != "" {
		t.Fatalf("plain asset after completion: %+v, %v", p, err)
	}
}

func TestPlaybackSessionStoresItsVariant(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := readyAsset(t, r, f)
	now := micro(time.Now())

	def := newSession(f, a, "viewer-1", now) // no variant: original
	s, err := r.InsertPlaybackSession(ctx, def)
	if err != nil || s.Variant != keys.Original {
		t.Fatalf("default variant: %+v, %v", s, err)
	}
	m := newSession(f, a, "viewer-2", now)
	m.Variant = keys.Masked
	if s, err = r.InsertPlaybackSession(ctx, m); err != nil || s.Variant != keys.Masked {
		t.Fatalf("masked variant: %+v, %v", s, err)
	}
	got, err := r.GetPlaybackSession(ctx, f.tenant.ID, db.SessionHash(m.ID))
	if err != nil || got.Variant != keys.Masked {
		t.Fatalf("read back: %+v, %v", got, err)
	}
	bad := newSession(f, a, "viewer-3", now)
	bad.Variant = "other"
	if _, err := r.InsertPlaybackSession(ctx, bad); err == nil {
		t.Fatal("accepted an unknown variant")
	}
}
