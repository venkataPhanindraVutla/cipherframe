package db

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// TestAssetStateMachineIsExhaustive checks every ordered pair of states against the table the
// lifecycle is documented with. A new state or edge must be added here on purpose.
func TestAssetStateMachineIsExhaustive(t *testing.T) {
	allowed := map[[2]AssetState]bool{
		{AssetCreated, AssetUploading}:    true,
		{AssetCreated, AssetFailed}:       true,
		{AssetCreated, AssetDeleting}:     true,
		{AssetUploading, AssetCommitted}:  true,
		{AssetUploading, AssetFailed}:     true,
		{AssetUploading, AssetDeleting}:   true,
		{AssetCommitted, AssetProcessing}: true,
		{AssetCommitted, AssetFailed}:     true,
		{AssetCommitted, AssetDeleting}:   true,
		{AssetProcessing, AssetReady}:     true,
		{AssetProcessing, AssetFailed}:    true,
		{AssetProcessing, AssetDeleting}:  true,
		{AssetReady, AssetDeleting}:       true,
		{AssetFailed, AssetDeleting}:      true,
		{AssetDeleting, AssetDeleted}:     true,
	}
	states := AssetStates()
	if len(states) != 8 {
		t.Fatalf("AssetStates() has %d states, want 8", len(states))
	}
	seen := map[AssetState]bool{}
	for _, s := range states {
		if !s.Valid() {
			t.Fatalf("%q is listed but not valid", s)
		}
		if seen[s] {
			t.Fatalf("%q is listed twice", s)
		}
		seen[s] = true
	}
	for _, from := range states {
		for _, to := range states {
			want := allowed[[2]AssetState{from, to}]
			if got := from.CanTransitionTo(to); got != want {
				t.Errorf("%s -> %s: allowed = %v, want %v", from, to, got, want)
			}
		}
	}
	if AssetState("bogus").CanTransitionTo(AssetFailed) || AssetCreated.CanTransitionTo("bogus") {
		t.Error("an unknown state must not transition")
	}
	for _, s := range states {
		if got, want := s.Terminal(), s == AssetDeleted; got != want {
			t.Errorf("%s.Terminal() = %v, want %v", s, got, want)
		}
	}
}

func TestAssetStateMachineHasNoBackwardEdgeToCreated(t *testing.T) {
	for _, from := range AssetStates() {
		if from.CanTransitionTo(AssetCreated) {
			t.Errorf("%s -> created must not be allowed", from)
		}
	}
}

func TestAcceptingStates(t *testing.T) {
	for _, s := range AssetStates() {
		want := s == AssetCreated || s == AssetUploading
		if s.Accepting() != want {
			t.Errorf("%s.Accepting() = %v, want %v", s, s.Accepting(), want)
		}
	}
}

// TestAssetNeverPrintsItsKey proves the source key and upload ID stay out of every formatting
// verb and out of structured logs.
func TestAssetNeverPrintsItsKey(t *testing.T) {
	a := Asset{
		ID:         id.New[id.AssetKind](),
		State:      AssetUploading,
		SourceKey:  "t/ten/a/ast/source/SECRETRANDOM",
		S3UploadID: "SECRETUPLOADID",
	}
	var sb strings.Builder
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		fmt.Fprintf(&sb, verb+"\n", a)
		fmt.Fprintf(&sb, verb+"\n", &a)
	}
	h := slog.NewTextHandler(&sb, nil)
	slog.New(h).Info("asset", "asset", a)
	for _, banned := range []string{"SECRETRANDOM", "SECRETUPLOADID", "source/"} {
		if strings.Contains(sb.String(), banned) {
			t.Fatalf("output contains %q:\n%s", banned, sb.String())
		}
	}
}
