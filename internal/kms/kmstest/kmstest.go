// Package kmstest is the provider conformance suite (ADR 0023). Every kms.Provider runs it, so all
// providers agree on round trips, associated-data binding, tamper detection, input validation,
// mixed key versions and outage behaviour.
package kmstest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

// Option customises Run for a provider.
type Option func(*options)

type options struct {
	rotated func(t *testing.T) kms.Provider
	outage  func(t *testing.T, p kms.Provider) (restore func())
}

// WithRotated supplies a provider over the same keys whose current KEK is a later version than the
// provider built by newProvider. It enables the mixed-version test: a key wrapped before the
// rotation must still unwrap after it, and new wraps must use the new version.
func WithRotated(f func(t *testing.T) kms.Provider) Option {
	return func(o *options) { o.rotated = f }
}

// WithOutage supplies a hook that makes the provider's backend unreachable until the returned
// restore function runs. It enables the outage test: Wrap and Unwrap must fail with
// kms.ErrUnavailable and yield no key.
func WithOutage(f func(t *testing.T, p kms.Provider) (restore func())) Option {
	return func(o *options) { o.outage = f }
}

// Run executes the suite. newProvider returns a fresh, working provider for each subtest.
func Run(t *testing.T, newProvider func(t *testing.T) kms.Provider, opts ...Option) {
	t.Helper()
	var o options
	for _, f := range opts {
		f(&o)
	}
	ctx := context.Background()
	aad := []byte("aad-for-conformance")
	secret := func() []byte {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("name and current", func(t *testing.T) {
		p := newProvider(t)
		if p.Name() == "" {
			t.Fatal("Name is empty")
		}
		ref, err := p.Current(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ref.KeyID == "" || ref.Version == "" {
			t.Fatal("Current returned an incomplete KeyRef")
		}
	})

	t.Run("round trip", func(t *testing.T) {
		p := newProvider(t)
		pt := secret()
		w, err := p.Wrap(ctx, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := p.Current(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if w.Provider != p.Name() || w.Ref() != ref || len(w.Ciphertext) == 0 {
			t.Fatal("Wrapped does not record provider, key id and version of the current KEK")
		}
		if bytes.Contains(w.Ciphertext, pt) {
			t.Fatal("ciphertext contains the plaintext")
		}
		got, err := p.Unwrap(ctx, w, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatal("round trip changed the plaintext")
		}
	})

	t.Run("wraps are randomised", func(t *testing.T) {
		p := newProvider(t)
		pt := secret()
		a, err := p.Wrap(ctx, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		b, err := p.Wrap(ctx, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(a.Ciphertext, b.Ciphertext) {
			t.Fatal("wrapping twice produced identical ciphertext")
		}
	})

	t.Run("different aad fails", func(t *testing.T) {
		p := newProvider(t)
		w, err := p.Wrap(ctx, secret(), aad)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.Unwrap(ctx, w, []byte("another-aad"))
		if !errors.Is(err, kms.ErrInvalid) || got != nil {
			t.Fatalf("want ErrInvalid and no key, got %v", err)
		}
	})

	t.Run("tampered ciphertext fails", func(t *testing.T) {
		p := newProvider(t)
		w, err := p.Wrap(ctx, secret(), aad)
		if err != nil {
			t.Fatal(err)
		}
		for i := range w.Ciphertext {
			bad := w
			bad.Ciphertext = bytes.Clone(w.Ciphertext)
			bad.Ciphertext[i] ^= 0x01
			got, err := p.Unwrap(ctx, bad, aad)
			if err == nil || got != nil {
				t.Fatalf("flipping byte %d did not fail closed", i)
			}
			if k := kms.KindOf(err); k != kms.Invalid && k != kms.NotConfigured {
				t.Fatalf("flipping byte %d: kind %v", i, k)
			}
		}
		trunc := w
		trunc.Ciphertext = w.Ciphertext[:len(w.Ciphertext)-1]
		if got, err := p.Unwrap(ctx, trunc, aad); err == nil || got != nil {
			t.Fatal("truncated ciphertext did not fail closed")
		}
		empty := w
		empty.Ciphertext = nil
		if got, err := p.Unwrap(ctx, empty, aad); err == nil || got != nil {
			t.Fatal("empty ciphertext did not fail closed")
		}
	})

	t.Run("wrong provider name fails", func(t *testing.T) {
		p := newProvider(t)
		w, err := p.Wrap(ctx, secret(), aad)
		if err != nil {
			t.Fatal(err)
		}
		w.Provider = "someone-else"
		if got, err := p.Unwrap(ctx, w, aad); err == nil || got != nil {
			t.Fatal("a wrapped key of another provider was accepted")
		}
	})

	t.Run("empty plaintext rejected", func(t *testing.T) {
		p := newProvider(t)
		for _, pt := range [][]byte{nil, {}} {
			if _, err := p.Wrap(ctx, pt, aad); err == nil {
				t.Fatal("empty plaintext was wrapped")
			}
		}
	})

	t.Run("empty aad rejected", func(t *testing.T) {
		p := newProvider(t)
		if _, err := p.Wrap(ctx, secret(), nil); err == nil {
			t.Fatal("empty aad was accepted")
		}
	})

	t.Run("expired context maps to unavailable", func(t *testing.T) {
		p := newProvider(t)
		w, err := p.Wrap(ctx, secret(), aad)
		if err != nil {
			t.Fatal(err)
		}
		dead, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
		defer cancel()
		if _, err := p.Wrap(dead, secret(), aad); !errors.Is(err, kms.ErrUnavailable) {
			t.Fatalf("Wrap: want ErrUnavailable, got %v", err)
		}
		if got, err := p.Unwrap(dead, w, aad); !errors.Is(err, kms.ErrUnavailable) || got != nil {
			t.Fatalf("Unwrap: want ErrUnavailable and no key, got %v", err)
		}
		if _, err := p.Current(dead); !errors.Is(err, kms.ErrUnavailable) {
			t.Fatalf("Current: want ErrUnavailable, got %v", err)
		}
	})

	if o.outage != nil {
		t.Run("outage maps to unavailable", func(t *testing.T) {
			p := newProvider(t)
			w, err := p.Wrap(ctx, secret(), aad)
			if err != nil {
				t.Fatal(err)
			}
			restore := o.outage(t, p)
			defer restore()
			if _, err := p.Wrap(ctx, secret(), aad); !errors.Is(err, kms.ErrUnavailable) {
				t.Fatalf("Wrap: want ErrUnavailable, got %v", err)
			}
			if got, err := p.Unwrap(ctx, w, aad); !errors.Is(err, kms.ErrUnavailable) || got != nil {
				t.Fatalf("Unwrap: want ErrUnavailable and no key, got %v", err)
			}
		})
	}

	if o.rotated != nil {
		t.Run("mixed versions", func(t *testing.T) {
			// Read and wrap with the older provider before o.rotated runs: a provider whose
			// current KEK lives on a server (Vault) moves to the new version the moment the
			// rotation happens, so the old reference can only be captured before it.
			before := newProvider(t)
			oldRef, err := before.Current(ctx)
			if err != nil {
				t.Fatal(err)
			}
			ptOld, ptNew := secret(), secret()
			wOld, err := before.Wrap(ctx, ptOld, aad)
			if err != nil {
				t.Fatal(err)
			}
			after := o.rotated(t)
			if before.Name() != after.Name() {
				t.Fatal("rotated provider has a different name")
			}
			newRef, err := after.Current(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if oldRef == newRef {
				t.Fatal("rotation did not change the current KEK version")
			}
			wNew, err := after.Wrap(ctx, ptNew, aad)
			if err != nil {
				t.Fatal(err)
			}
			if wOld.Ref() != oldRef || wNew.Ref() != newRef {
				t.Fatal("wraps do not record the version that made them")
			}
			for name, c := range map[string]struct {
				w  kms.Wrapped
				pt []byte
			}{"old": {wOld, ptOld}, "new": {wNew, ptNew}} {
				got, err := after.Unwrap(ctx, c.w, aad)
				if err != nil || !bytes.Equal(got, c.pt) {
					t.Fatalf("after rotation, the %s key did not unwrap: %v", name, err)
				}
			}
		})
	}
}
