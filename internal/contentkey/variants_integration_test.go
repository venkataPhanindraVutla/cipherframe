//go:build integration

package contentkey_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Each variant has its own key; re-wrap moves all of them; Destroy removes all of them.
func TestContentKeysPerVariantRewrapAndDestroy(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	asset := e.newAsset(t, e.tenant, e.client)

	made := map[keys.Variant][]byte{}
	for _, v := range []keys.Variant{keys.Original, keys.Masked} {
		var k contentkey.ContentKey
		if err := db.Tx(ctx, e.pool, func(tx *db.Repos) (err error) {
			k, err = e.mgr.Create(ctx, tx, e.tenant.ID, asset, v)
			return err
		}); err != nil {
			t.Fatalf("Create(%s): %v", v, err)
		}
		made[v] = k.Bytes()
		k.Zero()
	}
	if bytes.Equal(made[keys.Original], made[keys.Masked]) {
		t.Fatal("two variants share one key")
	}
	// A second key of the same variant conflicts; an unknown variant is refused.
	err := db.Tx(ctx, e.pool, func(tx *db.Repos) error {
		_, err := e.mgr.Create(ctx, tx, e.tenant.ID, asset, keys.Masked)
		return err
	})
	wantCode(t, err, errs.Conflict)
	err = db.Tx(ctx, e.pool, func(tx *db.Repos) error {
		_, err := e.mgr.Create(ctx, tx, e.tenant.ID, asset, "other")
		return err
	})
	wantCode(t, err, errs.InvalidRequest)

	// Re-wrap covers every variant row.
	v2 := e.manager(t, localProvider(t, 2))
	for range 3 {
		if _, err := v2.Rewrap(ctx, 1, nil); err != nil {
			t.Fatal(err)
		}
	}
	if u := e.usage(t); len(u) != 1 || u[0].KEK != localKEK("2") || u[0].Keys != 2 {
		t.Fatalf("usage after = %+v", u)
	}
	for v, want := range made {
		got, err := v2.Get(ctx, e.tenant.ID, asset, v)
		if err != nil || !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("Get(%s) after re-wrap: %v", v, err)
		}
		got.Zero()
	}

	// Destroy shreds both.
	ok, err := e.destroy(ctx, e.tenant.ID, asset)
	if err != nil || !ok {
		t.Fatalf("Destroy = %v, %v", ok, err)
	}
	for v := range made {
		_, err := v2.Get(ctx, e.tenant.ID, asset, v)
		wantCode(t, err, errs.NotFound)
	}
	if n := countRows(t, e.pool); n != 0 {
		t.Fatalf("%d rows survived Destroy", n)
	}
}
