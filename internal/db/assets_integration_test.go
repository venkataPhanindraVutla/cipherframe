//go:build integration

package db_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

func newUploadAsset(t *testing.T, r *db.Repos, f fixture, method db.UploadMethod) db.Asset {
	t.Helper()
	a, err := r.CreateUploadAsset(context.Background(), db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: f.tenant.ID, ClientID: f.client.ID, SizeBytes: 1234,
		ContentType: "video/mp4", Method: method, SourceKey: "t/x/a/y/source/" + id.New[id.AssetKind]().String(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestUploadAssetCreateAndRead(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := newUploadAsset(t, r, f, db.UploadTus)
	if a.State != db.AssetCreated || a.SizeBytes != 1234 || a.ContentType != "video/mp4" || a.UploadMethod != db.UploadTus ||
		a.SourceKey == "" || a.S3UploadID != "" || a.UploadExpiresAt == nil || a.CommittedAt != nil || a.FailureCode != "" {
		t.Fatalf("unexpected asset: %+v", a)
	}
	got, err := r.GetAsset(ctx, f.tenant.ID, a.ID)
	if err != nil || got.SourceKey != a.SourceKey || got.SizeBytes != a.SizeBytes {
		t.Fatalf("GetAsset = %+v, %v", got, err)
	}

	// The client must belong to the tenant.
	other := newFixture(t, r, "other")
	_, err = r.CreateUploadAsset(ctx, db.NewUploadAsset{
		ID: id.New[id.AssetKind](), TenantID: f.tenant.ID, ClientID: other.client.ID, SizeBytes: 1,
		Method: db.UploadTus, SourceKey: "k", ExpiresAt: time.Now(),
	})
	wantCode(t, err, errs.NotFound)
	// Invalid input never reaches the database.
	for name, in := range map[string]db.NewUploadAsset{
		"zero size":      {ID: id.New[id.AssetKind](), TenantID: f.tenant.ID, ClientID: f.client.ID, SizeBytes: 0, Method: db.UploadTus, SourceKey: "k"},
		"bad method":     {ID: id.New[id.AssetKind](), TenantID: f.tenant.ID, ClientID: f.client.ID, SizeBytes: 1, Method: "ftp", SourceKey: "k"},
		"no source key":  {ID: id.New[id.AssetKind](), TenantID: f.tenant.ID, ClientID: f.client.ID, SizeBytes: 1, Method: db.UploadTus},
		"no asset id":    {TenantID: f.tenant.ID, ClientID: f.client.ID, SizeBytes: 1, Method: db.UploadTus, SourceKey: "k"},
		"no tenant":      {ID: id.New[id.AssetKind](), ClientID: f.client.ID, SizeBytes: 1, Method: db.UploadTus, SourceKey: "k"},
		"no client":      {ID: id.New[id.AssetKind](), TenantID: f.tenant.ID, SizeBytes: 1, Method: db.UploadTus, SourceKey: "k"},
		"duplicate key":  {ID: id.New[id.AssetKind](), TenantID: f.tenant.ID, ClientID: f.client.ID, SizeBytes: 1, Method: db.UploadTus, SourceKey: a.SourceKey},
		"negative size":  {ID: id.New[id.AssetKind](), TenantID: f.tenant.ID, ClientID: f.client.ID, SizeBytes: -5, Method: db.UploadTus, SourceKey: "k2"},
		"huge but valid": {ID: id.New[id.AssetKind](), TenantID: f.tenant.ID, ClientID: f.client.ID, SizeBytes: 1 << 40, Method: db.UploadTus, SourceKey: "k3"},
	} {
		in.ExpiresAt = time.Now()
		_, err := r.CreateUploadAsset(ctx, in)
		if name == "huge but valid" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTransitionAssetIsCompareAndSet(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := newUploadAsset(t, r, f, db.UploadMultipart)
	at := time.Now().UTC().Truncate(time.Microsecond)

	// Wrong expected state: conflict, and nothing changes.
	_, err := r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: db.AssetUploading, To: db.AssetCommitted, At: at})
	wantCode(t, err, errs.Conflict)
	if !errors.Is(err, db.ErrStateChanged) {
		t.Fatalf("the conflict does not carry ErrStateChanged: %v", err)
	}
	if got, _ := r.GetAsset(ctx, f.tenant.ID, a.ID); got.State != db.AssetCreated || got.CommittedAt != nil {
		t.Fatalf("a refused transition changed the row: %+v", got)
	}
	// An edge the lifecycle does not have is a programming error, never sent to the database.
	_, err = r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: db.AssetCreated, To: db.AssetReady, At: at})
	wantCode(t, err, errs.InternalError)
	_, err = r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: db.AssetCreated, To: db.AssetCreated, At: at})
	wantCode(t, err, errs.InternalError)

	walk := []struct {
		from, to db.AssetState
		stamp    func(db.Asset) *time.Time
	}{
		{db.AssetCreated, db.AssetUploading, nil},
		{db.AssetUploading, db.AssetCommitted, func(a db.Asset) *time.Time { return a.CommittedAt }},
		{db.AssetCommitted, db.AssetProcessing, func(a db.Asset) *time.Time { return a.ProcessingStartedAt }},
		{db.AssetProcessing, db.AssetReady, func(a db.Asset) *time.Time { return a.ReadyAt }},
	}
	for _, step := range walk {
		got, err := r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: step.from, To: step.to, At: at})
		if err != nil || got.State != step.to {
			t.Fatalf("%s -> %s: %+v, %v", step.from, step.to, got, err)
		}
		if step.stamp != nil {
			if ts := step.stamp(got); ts == nil || !ts.Equal(at) {
				t.Fatalf("%s: timestamp = %v, want %v", step.to, ts, at)
			}
		}
	}
	// The edges into deleting and deleted carry data (reason, times) and have their own methods
	// (RequestAssetDeletion, CompleteAssetDeletion); the generic transition refuses them.
	_, err = r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: db.AssetReady, To: db.AssetDeleting, At: at})
	wantCode(t, err, errs.InternalError)
	_, err = r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: db.AssetDeleting, To: db.AssetDeleted, At: at})
	wantCode(t, err, errs.InternalError)

	// Failing records the code and the time; a transition elsewhere does not touch them.
	b := newUploadAsset(t, r, f, db.UploadTus)
	got, err := r.TransitionAsset(ctx, f.tenant.ID, b.ID, db.Transition{
		From: db.AssetCreated, To: db.AssetFailed, FailureCode: "upload_aborted", At: at,
	})
	if err != nil || got.FailureCode != "upload_aborted" || got.FailedAt == nil || !got.FailedAt.Equal(at) {
		t.Fatalf("failed transition: %+v, %v", got, err)
	}

	// Another tenant's asset is untouchable.
	other := newFixture(t, r, "other")
	c := newUploadAsset(t, r, f, db.UploadTus)
	_, err = r.TransitionAsset(ctx, other.tenant.ID, c.ID, db.Transition{From: db.AssetCreated, To: db.AssetUploading, At: at})
	wantCode(t, err, errs.Conflict)
	if got, _ := r.GetAsset(ctx, f.tenant.ID, c.ID); got.State != db.AssetCreated {
		t.Fatal("another tenant changed the asset")
	}
}

func TestTransitionRaceHasOneWinner(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := newUploadAsset(t, r, f, db.UploadMultipart)
	if _, err := r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: db.AssetCreated, To: db.AssetUploading}); err != nil {
		t.Fatal(err)
	}
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.TransitionAsset(ctx, f.tenant.ID, a.ID, db.Transition{From: db.AssetUploading, To: db.AssetCommitted})
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, db.ErrStateChanged):
				conflicts.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || conflicts.Load() != 15 {
		t.Fatalf("%d winners and %d conflicts, want 1 and 15", wins.Load(), conflicts.Load())
	}
}

func TestStartTusUploadHappensOnce(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := newUploadAsset(t, r, f, db.UploadTus)
	got, err := r.StartTusUpload(ctx, f.tenant.ID, a.ID, "mp-1", time.Now())
	if err != nil || got.State != db.AssetUploading || got.S3UploadID != "mp-1" {
		t.Fatalf("StartTusUpload = %+v, %v", got, err)
	}
	_, err = r.StartTusUpload(ctx, f.tenant.ID, a.ID, "mp-2", time.Now())
	wantCode(t, err, errs.Conflict)
	if cur, _ := r.GetAsset(ctx, f.tenant.ID, a.ID); cur.S3UploadID != "mp-1" {
		t.Fatalf("the second start replaced the upload ID: %q", cur.S3UploadID)
	}
	// Only tus assets start this way.
	m := newUploadAsset(t, r, f, db.UploadMultipart)
	_, err = r.StartTusUpload(ctx, f.tenant.ID, m.ID, "mp", time.Now())
	wantCode(t, err, errs.Conflict)
	_, err = r.StartTusUpload(ctx, f.tenant.ID, a.ID, "", time.Now())
	wantCode(t, err, errs.InvalidRequest)

	// LockAsset serialises: a second transaction waits for the first.
	b := newUploadAsset(t, r, f, db.UploadTus)
	var order []string
	var mu sync.Mutex
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }
	hold := make(chan struct{})
	locked := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = db.Tx(ctx, pool, func(tx *db.Repos) error {
			if _, err := tx.LockAsset(ctx, f.tenant.ID, b.ID); err != nil {
				return err
			}
			close(locked)
			<-hold
			note("first done")
			return nil
		})
	}()
	<-locked
	go func() {
		defer wg.Done()
		_ = db.Tx(ctx, pool, func(tx *db.Repos) error {
			_, err := tx.LockAsset(ctx, f.tenant.ID, b.ID)
			note("second locked")
			return err
		})
	}()
	time.Sleep(300 * time.Millisecond)
	close(hold)
	wg.Wait()
	if len(order) != 2 || order[0] != "first done" {
		t.Fatalf("lock order = %v", order)
	}
}

func TestListAssetsPage(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	other := newFixture(t, r, "other")
	var want []id.AssetID
	for range 5 {
		want = append(want, newUploadAsset(t, r, f, db.UploadTus).ID)
	}
	deleted := newUploadAsset(t, r, f, db.UploadTus)
	if _, err := r.RequestAssetDeletion(ctx, f.tenant.ID, deleted.ID, db.DeletionRequested, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CompleteAssetDeletion(ctx, f.tenant.ID, deleted.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	newUploadAsset(t, r, other, db.UploadTus)

	var got []id.AssetID
	var after id.AssetID
	for {
		page, err := r.ListAssetsPage(ctx, f.tenant.ID, after, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, a := range page {
			got = append(got, a.ID)
		}
		after = page[len(page)-1].ID
	}
	if len(got) != len(want) {
		t.Fatalf("listed %d assets, want %d (deleted and other tenants' assets are excluded)", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order differs at %d", i)
		}
	}
	_, err := r.ListAssetsPage(ctx, f.tenant.ID, id.AssetID{}, 0)
	wantCode(t, err, errs.InvalidRequest)
}

func TestUploadTokensAndParts(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a := newUploadAsset(t, r, f, db.UploadMultipart)
	hash := bytes.Repeat([]byte{7}, 32)
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)

	if err := r.InsertUploadToken(ctx, f.tenant.ID, a.ID, hash, exp); err != nil {
		t.Fatal(err)
	}
	g, err := r.GetUploadGrant(ctx, hash)
	if err != nil || g.Asset.ID != a.ID || !g.TokenExpiresAt.Equal(exp) {
		t.Fatalf("grant = %+v, %v", g, err)
	}
	_, err = r.GetUploadGrant(ctx, bytes.Repeat([]byte{8}, 32))
	wantCode(t, err, errs.NotFound)
	// One token per asset, and the hash must be a SHA-256.
	wantCode(t, r.InsertUploadToken(ctx, f.tenant.ID, a.ID, bytes.Repeat([]byte{9}, 32), exp), errs.Conflict)
	wantCode(t, r.InsertUploadToken(ctx, f.tenant.ID, a.ID, []byte("short"), exp), errs.InternalError)

	// Parts.
	for _, p := range []db.UploadPart{{PartNumber: 3, ETag: `"c"`, SizeBytes: 30}, {PartNumber: 1, ETag: `"a"`, SizeBytes: 10}} {
		if err := r.RecordUploadPart(ctx, a.ID, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.RecordUploadPart(ctx, a.ID, db.UploadPart{PartNumber: 1, ETag: `"a2"`, SizeBytes: 11}); err != nil { // replaced
		t.Fatal(err)
	}
	parts, err := r.ListUploadParts(ctx, a.ID)
	if err != nil || len(parts) != 2 || parts[0].PartNumber != 1 || parts[0].ETag != `"a2"` || parts[0].SizeBytes != 11 || parts[1].PartNumber != 3 {
		t.Fatalf("parts = %+v, %v", parts, err)
	}
	if n, err := r.SumOtherUploadPartSizes(ctx, a.ID, 1); err != nil || n != 30 {
		t.Fatalf("sum without part 1 = %d, %v", n, err)
	}
	if n, err := r.SumOtherUploadPartSizes(ctx, a.ID, 2); err != nil || n != 41 {
		t.Fatalf("sum without part 2 = %d, %v", n, err)
	}
	for _, bad := range []db.UploadPart{{PartNumber: 0, ETag: "e", SizeBytes: 1}, {PartNumber: 10001, ETag: "e", SizeBytes: 1}, {PartNumber: 1, ETag: "", SizeBytes: 1}, {PartNumber: 1, ETag: "e", SizeBytes: 0}} {
		wantCode(t, r.RecordUploadPart(ctx, a.ID, bad), errs.InvalidRequest)
	}

	if err := r.DeleteUploadTokens(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	_, err = r.GetUploadGrant(ctx, hash)
	wantCode(t, err, errs.NotFound)
	if err := r.DeleteUploadParts(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if parts, _ := r.ListUploadParts(ctx, a.ID); len(parts) != 0 {
		t.Fatalf("parts after delete: %+v", parts)
	}
}
