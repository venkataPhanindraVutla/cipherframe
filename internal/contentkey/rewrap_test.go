package contentkey

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
)

func localSet(t *testing.T, current int) *local.Provider {
	t.Helper()
	p, err := local.NewFromKeys(config.Development, map[int][]byte{
		1: bytes.Repeat([]byte{0x41}, config.KEKBytes),
		2: bytes.Repeat([]byte{0x42}, config.KEKBytes),
	}, current, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// rowUnder wraps key under p's current KEK the way Create does and returns the stored row.
func rowUnder(t *testing.T, p kms.Provider, key []byte) db.ContentKeyRow {
	t.Helper()
	ctx := context.Background()
	asset, keyID := id.New[id.AssetKind](), id.New[id.ContentKeyKind]()
	ref, err := p.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w, err := p.Wrap(ctx, key, AAD(Binding{
		EnvelopeVersion: EnvelopeVersion, AssetID: asset, ContentKeyID: keyID,
		Provider: p.Name(), KEKKeyID: ref.KeyID, KEKVersion: ref.Version,
	}))
	if err != nil {
		t.Fatal(err)
	}
	return db.ContentKeyRow{
		ID: keyID, AssetID: asset, EnvelopeVersion: EnvelopeVersion, Wrapped: w.Ciphertext,
		KEK: db.KEKRef{Provider: w.Provider, KeyID: w.KeyID, Version: w.Version},
	}
}

func rowBinding(r db.ContentKeyRow) []byte {
	return AAD(Binding{
		EnvelopeVersion: r.EnvelopeVersion, AssetID: r.AssetID, ContentKeyID: r.ID,
		Provider: r.KEK.Provider, KEKKeyID: r.KEK.KeyID, KEKVersion: r.KEK.Version,
	})
}

func newTestManager(t *testing.T, logs *bytes.Buffer, current kms.Provider, others ...kms.Provider) *Manager {
	t.Helper()
	reg, err := kms.NewRegistry(current, others...)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	if logs != nil {
		log = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return &Manager{reg: reg, log: log}
}

func TestRewrapRowKeepsKeyAndRebinds(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x7c}, KeyBytes)
	oldRow := rowUnder(t, localSet(t, 1), key)

	// The same provider, now current at version 2: its own old version still unwraps.
	v2 := localSet(t, 2)
	m := newTestManager(t, nil, v2)
	u, err := m.rewrapRow(ctx, oldRow)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != oldRow.ID || u.From != oldRow.KEK || u.To != (db.KEKRef{Provider: "local", KeyID: "local", Version: "2"}) {
		t.Fatalf("unexpected update: from %+v to %+v", u.From, u.To)
	}
	if bytes.Equal(u.Wrapped, oldRow.Wrapped) {
		t.Fatal("ciphertext did not change")
	}

	newRow := oldRow
	newRow.KEK, newRow.Wrapped = u.To, u.Wrapped
	// The same 16 key bytes come back under the new binding.
	got, err := v2.Unwrap(ctx, kms.Wrapped{Provider: "local", KeyID: "local", Version: "2", Ciphertext: u.Wrapped}, rowBinding(newRow))
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("new ciphertext does not unwrap to the same key under the new binding: %v", err)
	}
	// The old binding no longer authenticates the new ciphertext, and the old ciphertext does not
	// authenticate under the new binding.
	if _, err := v2.Unwrap(ctx, kms.Wrapped{Provider: "local", KeyID: "local", Version: "2", Ciphertext: u.Wrapped}, rowBinding(oldRow)); !errors.Is(err, kms.ErrInvalid) {
		t.Fatalf("new ciphertext under the old binding = %v, want ErrInvalid", err)
	}
	if _, err := v2.Unwrap(ctx, kms.Wrapped{Provider: "local", KeyID: "local", Version: "2", Ciphertext: oldRow.Wrapped}, rowBinding(newRow)); !errors.Is(err, kms.ErrInvalid) {
		t.Fatalf("old ciphertext under the new binding = %v, want ErrInvalid", err)
	}
}

func TestRewrapRowAcrossProviders(t *testing.T) {
	// "local" holds the old wrap; the current provider is a differently named one.
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x19}, KeyBytes)
	oldRow := rowUnder(t, localSet(t, 1), key)

	renamed := &renamedLocal{p: localSet(t, 2), name: "fake"}
	m := newTestManager(t, nil, renamed, localSet(t, 1))
	u, err := m.rewrapRow(ctx, oldRow)
	if err != nil {
		t.Fatal(err)
	}
	if u.To.Provider != "fake" || u.From.Provider != "local" {
		t.Fatalf("unexpected providers: %+v -> %+v", u.From, u.To)
	}
}

// renamedLocal presents a local provider under another name, recording that name in its wraps.
type renamedLocal struct {
	p    *local.Provider
	name string
}

func (r *renamedLocal) Name() string { return r.name }
func (r *renamedLocal) Current(ctx context.Context) (kms.KeyRef, error) {
	return r.p.Current(ctx)
}

func (r *renamedLocal) Wrap(ctx context.Context, pt, aad []byte) (kms.Wrapped, error) {
	w, err := r.p.Wrap(ctx, pt, aad)
	w.Provider = r.name
	return w, err
}

func (r *renamedLocal) Unwrap(ctx context.Context, w kms.Wrapped, aad []byte) ([]byte, error) {
	w.Provider = "local"
	return r.p.Unwrap(ctx, w, aad)
}

func TestRewrapRowOutageLeavesNothing(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x23}, KeyBytes)
	oldRow := rowUnder(t, localSet(t, 1), key)

	for _, tc := range []struct {
		name   string
		budget int // provider calls allowed before the outage
	}{
		{"unwrap fails", 0},
		{"wrap fails", 1},
		{"verifying unwrap fails", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := kmstest.NewFaulty(localSet(t, 2))
			f.FailAfter(tc.budget)
			m := newTestManager(t, nil, f)
			u, err := m.rewrapRow(ctx, oldRow)
			var e *errs.Error
			if !errors.As(err, &e) || e.Code != errs.DependencyUnavailable {
				t.Fatalf("got %v, want dependency_unavailable", err)
			}
			if len(u.Wrapped) != 0 {
				t.Fatal("an outage produced a ciphertext to store")
			}
		})
	}
}

func TestRewrapRowIntegrityFailure(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x23}, KeyBytes)
	oldRow := rowUnder(t, localSet(t, 1), key)

	var logs bytes.Buffer
	f := kmstest.NewFaulty(localSet(t, 2))
	f.SetIntegrityFailure(true)
	m := newTestManager(t, &logs, f)
	_, err := m.rewrapRow(ctx, oldRow)
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != errs.InternalError || !kms.IsIntegrityFailure(err) {
		t.Fatalf("got %v, want an internal_error integrity failure", err)
	}
	out := logs.String()
	if !strings.Contains(out, "content key failed authentication (integrity failure)") ||
		!strings.Contains(out, oldRow.ID.String()) {
		t.Fatalf("integrity failure not logged with ids: %s", out)
	}
	if strings.Contains(out, "injected") {
		t.Fatal("the log carries provider error text")
	}

	// Tampered ciphertext in the row itself is the same failure with a real provider.
	bad := oldRow
	bad.Wrapped = append([]byte(nil), oldRow.Wrapped...)
	bad.Wrapped[len(bad.Wrapped)-1] ^= 1
	_, err = newTestManager(t, nil, localSet(t, 2)).rewrapRow(ctx, bad)
	if !kms.IsIntegrityFailure(err) {
		t.Fatalf("tampered row: got %v, want an integrity failure", err)
	}
}

func TestRewrapRowRefusesUnsupportedEnvelope(t *testing.T) {
	row := rowUnder(t, localSet(t, 1), bytes.Repeat([]byte{1}, KeyBytes))
	row.EnvelopeVersion = 9
	if _, err := newTestManager(t, nil, localSet(t, 2)).rewrapRow(context.Background(), row); err == nil {
		t.Fatal("an unsupported envelope version was re-wrapped")
	}
}

func TestRewrapRowUnconfiguredProvider(t *testing.T) {
	row := rowUnder(t, localSet(t, 1), bytes.Repeat([]byte{1}, KeyBytes))
	row.KEK.Provider = "vault"
	if _, err := newTestManager(t, nil, localSet(t, 2)).rewrapRow(context.Background(), row); !errors.Is(err, kms.ErrNotConfigured) {
		t.Fatalf("got %v, want ErrNotConfigured", err)
	}
}

func TestRewrapBatchValidation(t *testing.T) {
	m := newTestManager(t, nil, localSet(t, 1))
	if _, err := m.Rewrap(context.Background(), 5, nil); err == nil {
		t.Fatal("a manager without a transaction source must refuse to re-wrap")
	}
}
