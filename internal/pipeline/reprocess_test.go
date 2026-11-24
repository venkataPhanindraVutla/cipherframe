package pipeline

import (
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// A storage outage fails the asset on its last attempt. After the reprocess request has moved it back
// to committed (db.Repos.RequeueFailedAsset), the same job kind runs again from a clean state, uses the
// content key the first run created, and the asset becomes ready with exactly its registered objects.
func TestReprocessedAssetStartsCleanReusesTheKeyAndBecomesReady(t *testing.T) {
	h := newHarness(t)
	h.delivery.putFailAfter = 6
	if err := h.run(5, 5); err == nil || isCancel(err) {
		t.Fatalf("last attempt error = %v", err)
	}
	if a := h.repo.snapshot(); a.State != db.AssetFailed || a.FailureCode != FailureProcessing {
		t.Fatalf("asset = %s/%s, want failed/%s", a.State, a.FailureCode, FailureProcessing)
	}
	if n := len(h.delivery.keys()); n != 0 {
		t.Fatalf("the failure left %d objects", n)
	}
	// A failed asset is finished for the job: a stray job does nothing.
	if err := h.run(1, 5); err != nil || h.repo.snapshot().State != db.AssetFailed {
		t.Fatalf("job for a failed asset: %v, state %s", err, h.repo.snapshot().State)
	}

	// What the reprocess request does to the row, and a leftover its failure path could have missed.
	h.repo.mu.Lock()
	h.repo.asset.State, h.repo.asset.FailureCode, h.repo.asset.Progress = db.AssetCommitted, "", 0
	h.repo.mu.Unlock()
	h.repo.artifacts["delivery/stale"] = db.Artifact{ObjectKey: "stale"}
	h.delivery.objects[keys.HLSPrefix(h.args.TenantID, h.args.AssetID)+"720p/seg-99.m4s"] = []byte("old")

	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	if a := h.repo.snapshot(); a.State != db.AssetReady {
		t.Fatalf("state after the reprocess = %s", a.State)
	}
	stored := h.delivery.keys()
	if len(stored) != len(h.repo.artifacts) || len(stored) != 24 {
		t.Fatalf("%d objects vs %d artifacts", len(stored), len(h.repo.artifacts))
	}
	for _, k := range stored {
		if strings.Contains(k, "seg-99") {
			t.Error("a leftover of the failed run survived")
		}
	}
	if h.keys.creates != 1 {
		t.Errorf("content key created %d times; the first run's key must be reused", h.keys.creates)
	}
}
