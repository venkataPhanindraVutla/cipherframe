package kms_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

type stub struct{ name string }

func (s stub) Name() string { return s.name }
func (stub) Current(context.Context) (kms.KeyRef, error) {
	return kms.KeyRef{KeyID: "k", Version: "1"}, nil
}

func (s stub) Wrap(context.Context, []byte, []byte) (kms.Wrapped, error) {
	return kms.Wrapped{Provider: s.name}, nil
}
func (stub) Unwrap(context.Context, kms.Wrapped, []byte) ([]byte, error) { return []byte("k"), nil }

func TestRegistry(t *testing.T) {
	r, err := kms.NewRegistry(stub{"local"}, stub{"vault"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Current().Name() != "local" {
		t.Fatal("wrong current provider")
	}
	if got := strings.Join(r.Names(), ","); got != "local,vault" {
		t.Fatalf("names = %s", got)
	}
	if p, err := r.Lookup("vault"); err != nil || p.Name() != "vault" {
		t.Fatal("lookup failed")
	}
	if _, err := r.Lookup("awskms"); !errors.Is(err, kms.ErrNotConfigured) {
		t.Fatalf("unconfigured provider: want ErrNotConfigured, got %v", err)
	}
	got, err := r.Unwrap(context.Background(), kms.Wrapped{Provider: "awskms"}, []byte("a"))
	if err == nil || got != nil {
		t.Fatal("unwrapping an unconfigured provider must fail, never pass")
	}
	if got, err := r.Unwrap(context.Background(), kms.Wrapped{Provider: "vault"}, []byte("a")); err != nil || got == nil {
		t.Fatal("routing to a configured provider failed")
	}
}

func TestRegistryRejectsBadInput(t *testing.T) {
	if _, err := kms.NewRegistry(nil); err == nil {
		t.Fatal("nil current provider accepted")
	}
	if _, err := kms.NewRegistry(stub{"local"}, stub{"local"}); err == nil {
		t.Fatal("duplicate provider accepted")
	}
	if _, err := kms.NewRegistry(stub{""}); err == nil {
		t.Fatal("unnamed provider accepted")
	}
}

func TestToAppError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want errs.Code
	}{
		{"unavailable", kms.New(kms.Unavailable, "local", "wrap", "x"), errs.DependencyUnavailable},
		{"sentinel unavailable", kms.ErrUnavailable, errs.DependencyUnavailable},
		{"wrapped unavailable", fmt.Errorf("ctx: %w", kms.ErrUnavailable), errs.DependencyUnavailable},
		{"denied", kms.ErrDenied, errs.InternalError},
		{"invalid", kms.ErrInvalid, errs.InternalError},
		{"not configured", kms.ErrNotConfigured, errs.InternalError},
		{"other", kms.ErrOther, errs.InternalError},
		{"foreign error", errors.New("boom"), errs.InternalError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var e *errs.Error
			if !errors.As(kms.ToAppError(tc.err), &e) || e.Code != tc.want {
				t.Fatalf("want code %s, got %v", tc.want, kms.ToAppError(tc.err))
			}
			if !errors.Is(kms.ToAppError(tc.err), tc.err) {
				t.Fatal("cause lost")
			}
		})
	}
	if kms.ToAppError(nil) != nil {
		t.Fatal("nil must map to nil")
	}
}

func TestToAppErrorKeepsAppErrors(t *testing.T) {
	in := errs.New(errs.Conflict, "x")
	if kms.ToAppError(in) != error(in) {
		t.Fatal("an *errs.Error must pass through unchanged")
	}
}

func TestErrorKinds(t *testing.T) {
	if kms.KindOf(nil) != kms.Other || kms.KindOf(errors.New("x")) != kms.Other {
		t.Fatal("unknown errors must be Other, never Invalid")
	}
	if kms.IsIntegrityFailure(errors.New("x")) || kms.IsIntegrityFailure(nil) || kms.IsIntegrityFailure(kms.ErrUnavailable) {
		t.Fatal("only Invalid is an integrity failure")
	}
	if !kms.IsIntegrityFailure(fmt.Errorf("w: %w", kms.New(kms.Invalid, "local", "unwrap", "x"))) {
		t.Fatal("Invalid must be an integrity failure")
	}
	if errors.Is(kms.New(kms.Invalid, "local", "unwrap", "x"), kms.ErrDenied) {
		t.Fatal("kinds must not match each other")
	}
}

func TestFromContext(t *testing.T) {
	if kms.FromContext(context.Background(), "local", "wrap") != nil {
		t.Fatal("a live context is not an error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := kms.FromContext(ctx, "local", "wrap")
	if !errors.Is(e, kms.ErrUnavailable) || !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled context must be unavailable and keep its cause")
	}
}
