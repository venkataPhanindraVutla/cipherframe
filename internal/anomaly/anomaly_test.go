package anomaly

import (
	"context"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/accesslog"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

func TestNilAndUnconfiguredDetectorsDoNothing(t *testing.T) {
	var nilDetector *Detector
	sig := Signal{Tenant: id.New[id.TenantKind](), Asset: id.New[id.AssetKind](), Session: make([]byte, 32), Kind: db.EventKeyRate}
	if out := nilDetector.Raise(context.Background(), sig); out != (Outcome{}) {
		t.Fatalf("outcome = %+v", out)
	}
	nilDetector.SegmentsServed(context.Background(), []accesslog.SegmentCount{{Count: 1}})
	// No pool: nothing can be stored, so nothing happens (and nothing panics).
	if out := New(Deps{}).Raise(context.Background(), sig); out != (Outcome{}) {
		t.Fatalf("outcome = %+v", out)
	}
}

func TestWindows(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, k := range []string{db.EventKeyReplay, db.EventKeyRate, db.EventSessionLimit, db.EventRapidSessionCreation} {
		if got := since(k, at); !got.Equal(at.Add(-10 * time.Minute)) {
			t.Errorf("%s window starts %v", k, got)
		}
	}
	// Once per session for the life of the session.
	if got := since(db.EventSegmentsWithoutKey, at); !got.Before(at.AddDate(-30, 0, 0)) {
		t.Errorf("segments_without_key window starts %v", got)
	}
}

func TestViewerLevelKinds(t *testing.T) {
	for kind, want := range map[string]bool{
		db.EventSessionLimit: true, db.EventRapidSessionCreation: true,
		db.EventKeyReplay: false, db.EventKeyRate: false, db.EventSegmentsWithoutKey: false,
	} {
		if viewerLevel(kind) != want {
			t.Errorf("viewerLevel(%s) = %v", kind, !want)
		}
	}
	// Every kind a tenant may auto-revoke is a kind that exists.
	for _, k := range db.AutoRevokeKinds {
		if !db.ValidEventKind(k) {
			t.Errorf("%s is auto-revocable but not an event kind", k)
		}
	}
	if db.ValidAutoRevokeKind(db.EventSessionLimit) {
		t.Error("session_limit must not be auto-revocable")
	}
}
