//go:build integration

package db_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

var kekV1 = db.KEKRef{Provider: "local", KeyID: "local", Version: "1"}

func newRow(assetID id.AssetID, kek db.KEKRef) db.NewContentKeyRow {
	return db.NewContentKeyRow{
		ID: id.New[id.ContentKeyKind](), AssetID: assetID, Variant: keys.Original, KEK: kek,
		EnvelopeVersion: 1, Wrapped: bytes.Repeat([]byte{7}, 45),
	}
}

func TestContentKeyRepo(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a, err := r.CreateAsset(ctx, f.tenant.ID, f.client.ID, db.AssetCreated)
	if err != nil {
		t.Fatal(err)
	}

	in := newRow(a.ID, kekV1)
	row, err := r.CreateContentKey(ctx, f.tenant.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	if row.ID != in.ID || row.AssetID != a.ID || row.KEK != kekV1 || row.EnvelopeVersion != 1 ||
		!bytes.Equal(row.Wrapped, in.Wrapped) || row.RewrappedAt != nil || row.CreatedAt.IsZero() {
		t.Fatalf("unexpected row: %+v", row)
	}
	got, err := r.GetContentKey(ctx, f.tenant.ID, a.ID, keys.Original)
	if err != nil || got.ID != row.ID {
		t.Fatalf("GetContentKey = %+v, %v", got, err)
	}

	// One key per asset (I7): a second insert conflicts and leaves the first untouched.
	_, err = r.CreateContentKey(ctx, f.tenant.ID, newRow(a.ID, kekV1))
	wantCode(t, err, errs.Conflict)
	got, err = r.GetContentKey(ctx, f.tenant.ID, a.ID, keys.Original)
	if err != nil || got.ID != row.ID {
		t.Fatal("the existing key changed after a conflicting insert")
	}

	// Invalid input.
	bad := newRow(a.ID, kekV1)
	bad.Wrapped = nil
	_, err = r.CreateContentKey(ctx, f.tenant.ID, bad)
	wantCode(t, err, errs.InvalidRequest)

	// Delete destroys the row.
	n, err := r.DeleteContentKey(ctx, f.tenant.ID, a.ID)
	if err != nil || n != 1 {
		t.Fatalf("DeleteContentKey = %d, %v", n, err)
	}
	_, err = r.GetContentKey(ctx, f.tenant.ID, a.ID, keys.Original)
	wantCode(t, err, errs.NotFound)
	if n, err := r.DeleteContentKey(ctx, f.tenant.ID, a.ID); err != nil || n != 0 {
		t.Fatalf("second delete = %d, %v; want 0", n, err)
	}
}

func TestContentKeyTenantIsolation(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f1 := newFixture(t, r, "acme")
	f2 := newFixture(t, r, "globex")
	a1, err := r.CreateAsset(ctx, f1.tenant.ID, f1.client.ID, db.AssetCreated)
	if err != nil {
		t.Fatal(err)
	}

	// Another tenant cannot attach a key to the asset.
	_, err = r.CreateContentKey(ctx, f2.tenant.ID, newRow(a1.ID, kekV1))
	wantCode(t, err, errs.NotFound)
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM content_keys").Scan(&n); err != nil || n != 0 {
		t.Fatalf("a cross-tenant insert left %d rows (err %v)", n, err)
	}

	if _, err := r.CreateContentKey(ctx, f1.tenant.ID, newRow(a1.ID, kekV1)); err != nil {
		t.Fatal(err)
	}
	_, err = r.GetContentKey(ctx, f2.tenant.ID, a1.ID, keys.Original)
	wantCode(t, err, errs.NotFound)
	if n, err := r.DeleteContentKey(ctx, f2.tenant.ID, a1.ID); err != nil || n != 0 {
		t.Fatalf("cross-tenant delete = %d, %v; want 0", n, err)
	}
	if _, err := r.GetContentKey(ctx, f1.tenant.ID, a1.ID, keys.Original); err != nil {
		t.Fatal("the owner's key was affected by another tenant")
	}
}

func TestContentKeyRewrapListing(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	kekV2 := db.KEKRef{Provider: "local", KeyID: "local", Version: "2"}

	var rows []db.ContentKeyRow
	for i := 0; i < 5; i++ {
		a, err := r.CreateAsset(ctx, f.tenant.ID, f.client.ID, db.AssetCreated)
		if err != nil {
			t.Fatal(err)
		}
		kek := kekV1
		if i == 4 {
			kek = kekV2
		}
		row, err := r.CreateContentKey(ctx, f.tenant.ID, newRow(a.ID, kek))
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}

	// Keyset pagination over the v1 rows: pages of 2, then the remainder.
	var seen []id.ContentKeyID
	var after id.ContentKeyID
	for {
		page, err := r.ListContentKeysForRewrap(ctx, kekV1, after, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range page {
			seen = append(seen, p.ID)
		}
		if len(page) < 2 {
			break
		}
		after = page[len(page)-1].ID
	}
	if len(seen) != 4 {
		t.Fatalf("listed %d v1 rows, want 4", len(seen))
	}
	for i := 0; i < 4; i++ {
		if seen[i] != rows[i].ID {
			t.Fatalf("row %d out of creation order", i)
		}
	}

	// Re-wrap one row: it moves to v2 and leaves the v1 listing.
	moved, err := r.UpdateContentKeyWrapped(ctx, db.RewrapUpdate{
		ID: rows[0].ID, From: kekV1, To: kekV2, EnvelopeVersion: 1, Wrapped: bytes.Repeat([]byte{9}, 45),
	})
	if err != nil || !moved {
		t.Fatalf("UpdateContentKeyWrapped = %v, %v", moved, err)
	}
	got, err := r.GetContentKey(ctx, f.tenant.ID, rows[0].AssetID, keys.Original)
	if err != nil || got.KEK != kekV2 || got.RewrappedAt == nil || !bytes.Equal(got.Wrapped, bytes.Repeat([]byte{9}, 45)) {
		t.Fatalf("after rewrap: %+v, %v", got, err)
	}
	// A stale update (the row no longer names v1) does nothing.
	moved, err = r.UpdateContentKeyWrapped(ctx, db.RewrapUpdate{
		ID: rows[0].ID, From: kekV1, To: kekV2, EnvelopeVersion: 1, Wrapped: bytes.Repeat([]byte{8}, 45),
	})
	if err != nil || moved {
		t.Fatalf("stale update = %v, %v; want false", moved, err)
	}
	page, err := r.ListContentKeysForRewrap(ctx, kekV1, id.ContentKeyID{}, 10)
	if err != nil || len(page) != 3 {
		t.Fatalf("v1 rows after rewrap = %d, %v; want 3", len(page), err)
	}

	_, err = r.ListContentKeysForRewrap(ctx, kekV1, id.ContentKeyID{}, 0)
	wantCode(t, err, errs.InvalidRequest)
}

func TestContentKeyRowsRequireAsset(t *testing.T) {
	ctx := context.Background()
	_, pool := newMigrated(t)
	// The foreign key and the unique constraint hold at the database level too.
	_, err := pool.Exec(ctx,
		"INSERT INTO content_keys (id, asset_id, provider, kek_key_id, kek_version, envelope_version, wrapped) "+
			"VALUES ($1, $2, 'local', 'local', '1', 1, '\\x01')",
		id.New[id.ContentKeyKind]().UUID(), id.New[id.AssetKind]().UUID())
	if err == nil {
		t.Fatal("a content key without an asset was accepted")
	}
}
