//go:build integration

package db_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

func testManifest(a db.Asset, f fixture) *db.AssetManifest {
	payload := sha256.Sum256([]byte("payload"))
	root := sha256.Sum256([]byte("root"))
	return &db.AssetManifest{
		AssetID: a.ID, TenantID: f.tenant.ID, KeyID: "sk_test",
		PayloadSHA256: payload[:], TopRoot: root[:], Envelope: []byte(`{"payloadType":"t","payload":"e30=","signatures":[]}`),
	}
}

func TestCompletionStoresTheManifestAtomically(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	summary, _ := json.Marshal([]map[string]any{{"name": "720p"}})

	// A manifest that cannot be stored rolls the whole completion back: the asset stays processing.
	a := processingAsset(t, r, f)
	broken := testManifest(a, f)
	broken.TopRoot = broken.TopRoot[:5]
	err := db.Tx(ctx, pool, func(tx *db.Repos) error {
		_, err := tx.CompleteProcessing(ctx, f.tenant.ID, a.ID, db.Completion{Duration: time.Second, Renditions: summary, Manifest: broken})
		return err
	})
	if err == nil {
		t.Fatal("accepted a manifest with a short root")
	}
	if got, _ := r.GetAsset(ctx, f.tenant.ID, a.ID); got.State != db.AssetProcessing {
		t.Fatalf("state after the failed completion = %s", got.State)
	}
	if _, err := r.GetManifest(ctx, a.ID); err == nil {
		t.Fatal("a manifest was stored by a rolled-back transaction")
	}

	// The same transaction with a good manifest gives a ready asset and its manifest.
	m := testManifest(a, f)
	err = db.Tx(ctx, pool, func(tx *db.Repos) error {
		_, err := tx.CompleteProcessing(ctx, f.tenant.ID, a.ID, db.Completion{Duration: time.Second, Renditions: summary, Manifest: m})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.GetManifest(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != "sk_test" || !bytes.Equal(got.PayloadSHA256, m.PayloadSHA256) || !bytes.Equal(got.TopRoot, m.TopRoot) ||
		got.TenantID != f.tenant.ID || got.CreatedAt.IsZero() {
		t.Fatalf("stored manifest = %+v", got)
	}
	var env map[string]any
	if err := json.Unmarshal(got.Envelope, &env); err != nil || env["payloadType"] != "t" {
		t.Fatalf("envelope = %s, %v", got.Envelope, err)
	}
	if a2, _ := r.GetAsset(ctx, f.tenant.ID, a.ID); a2.State != db.AssetReady {
		t.Fatalf("state = %s", a2.State)
	}

	// A second manifest for the same asset is a bug, not an upsert.
	if err := r.InsertManifest(ctx, *m); err == nil {
		t.Fatal("a duplicate manifest was accepted")
	}

	// A retry deletes it first.
	if ok, err := r.DeleteManifest(ctx, a.ID); err != nil || !ok {
		t.Fatalf("DeleteManifest = %v, %v", ok, err)
	}
	if ok, err := r.DeleteManifest(ctx, a.ID); err != nil || ok {
		t.Fatalf("second DeleteManifest = %v, %v", ok, err)
	}
	_, err = r.GetManifest(ctx, a.ID)
	wantCode(t, err, errs.NotFound)
}
