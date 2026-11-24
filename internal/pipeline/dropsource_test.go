package pipeline

import (
	"context"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

func TestDropDue(t *testing.T) {
	ready := db.Asset{State: db.AssetReady}
	cases := []struct {
		name string
		mod  func(*db.Asset)
		want bool
	}{
		{"keeps the source by default", func(a *db.Asset) { a.KeepSource = true }, false},
		{"drops when ready", func(*db.Asset) {}, true},
		{"already dropped", func(a *db.Asset) { now := a.CreatedAt; a.SourceDeletedAt = &now }, false},
		{"processing", func(a *db.Asset) { a.State = db.AssetProcessing }, false},
		{"failed", func(a *db.Asset) { a.State = db.AssetFailed }, false},
		{"deleting", func(a *db.Asset) { a.State = db.AssetDeleting }, false},
		{"deleted", func(a *db.Asset) { a.State = db.AssetDeleted }, false},
		{"mask pending (not set yet)", func(a *db.Asset) { a.MaskFaces = true }, false},
		{"mask pending", func(a *db.Asset) { a.MaskFaces, a.MaskingState = true, db.MaskingPending }, false},
		{"mask ready", func(a *db.Asset) { a.MaskFaces, a.MaskingState = true, db.MaskingReady }, true},
		{"mask failed", func(a *db.Asset) { a.MaskFaces, a.MaskingState = true, db.MaskingFailed }, true},
	}
	for _, c := range cases {
		a := ready
		c.mod(&a)
		if got := dropDue(a); got != c.want {
			t.Errorf("%s: dropDue = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestHandleDropSource(t *testing.T) {
	h := newHarness(t)
	a := h.repo.snapshot()
	h.repo.asset.State = db.AssetReady
	prefix := keys.SourcePrefix(a.TenantID, a.ID)
	h.source.objects[prefix+"x.info"] = []byte("info")
	h.source.objects["t/other/a/b/source/keep"] = []byte("another asset")
	run := func() error {
		return h.proc.HandleDropSource(context.Background(), jobs.Job[DropSourceArgs]{Args: DropSourceArgs{TenantID: a.TenantID, AssetID: a.ID}, Attempt: 1, MaxAttempts: 5})
	}

	// keep_source is true: nothing is deleted.
	h.repo.asset.KeepSource = true
	if err := run(); err != nil || len(h.source.keys()) != 3 || h.repo.snapshot().SourceDeletedAt != nil {
		t.Fatalf("with keep_source on: err=%v keys=%v", err, h.source.keys())
	}

	// Off: the original and its .info go, another asset's object stays, the time is recorded once.
	h.repo.asset.KeepSource = false
	for range 2 { // the second run is a retry and must change nothing
		if err := run(); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.source.keys(); len(got) != 1 || got[0] != "t/other/a/b/source/keep" {
		t.Fatalf("source bucket after the drop: %v", got)
	}
	if h.repo.snapshot().SourceDeletedAt == nil {
		t.Fatal("source_deleted_at was not recorded")
	}

	// A failed asset never runs it.
	h2 := newHarness(t)
	h2.repo.asset.State, h2.repo.asset.KeepSource = db.AssetFailed, false
	args := DropSourceArgs{TenantID: h2.args.TenantID, AssetID: h2.args.AssetID}
	if err := h2.proc.HandleDropSource(context.Background(), jobs.Job[DropSourceArgs]{Args: args}); err != nil || len(h2.source.keys()) != 1 {
		t.Fatalf("failed asset: err=%v keys=%v", err, h2.source.keys())
	}
}
