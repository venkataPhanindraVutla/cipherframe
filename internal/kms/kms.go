// Package kms defines the key-provider port of Cipherframe (M2-1, ADR 0019, ADR 0020): a
// KEK-holding service that wraps and unwraps content keys. Providers live in subpackages
// (local, later vault, awskms and gcpkms) and are assembled by package kms/registry.
//
// Every wrapped key records the provider, the KEK id and the KEK version that made it, so a key
// stays readable after the current KEK moves to a new version. Nothing in this package logs, and
// no error it returns contains plaintext, key material or a provider's own error text.
package kms

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// KeyRef names one version of a key-encryption key.
type KeyRef struct {
	KeyID   string
	Version string
}

// Wrapped is a wrapped (encrypted) key together with the provider, KEK id and KEK version that
// produced it. It carries no secret: Ciphertext is safe to store and to log as a length.
type Wrapped struct {
	Provider   string
	KeyID      string
	Version    string
	Ciphertext []byte
}

// Ref returns the KEK that wrapped w.
func (w Wrapped) Ref() KeyRef { return KeyRef{KeyID: w.KeyID, Version: w.Version} }

// Provider wraps and unwraps keys under a KEK held by a key-management service.
//
// The associated data aad is authenticated but not encrypted. Wrap and Unwrap must use the same
// aad, and a provider must fail Unwrap with ErrInvalid when it differs. Both methods reject empty
// input. Implementations must honour ctx: an expired or cancelled context fails with
// ErrUnavailable. A provider error never yields a key (invariant I11).
type Provider interface {
	// Name is the provider name: "local", "vault", "awskms" or "gcpkms".
	Name() string
	// Current returns the KEK that new wraps use.
	Current(ctx context.Context) (KeyRef, error)
	// Wrap encrypts plaintext under the current KEK. The result records provider, KEK id and
	// KEK version.
	Wrap(ctx context.Context, plaintext, aad []byte) (Wrapped, error)
	// Unwrap decrypts w, which may have been wrapped under any version the provider still holds.
	Unwrap(ctx context.Context, w Wrapped, aad []byte) ([]byte, error)
}

// KEKChecker is implemented by a provider that knows locally which KEK versions it holds (the
// local provider). Providers whose versions live in a remote service do not implement it; they can
// only be checked for presence.
type KEKChecker interface {
	// HasKEK reports whether ref names a KEK the provider can unwrap with.
	HasKEK(ref KeyRef) bool
}

// Registry holds the provider that wraps new keys and every configured provider that can unwrap,
// looked up by Wrapped.Provider. It is immutable after NewRegistry.
type Registry struct {
	current   Provider
	byName    map[string]Provider
	nameOrder []string
}

// NewRegistry returns a registry whose current provider wraps new keys. others are additional
// providers that can only unwrap keys they made earlier. Provider names must be unique.
func NewRegistry(current Provider, others ...Provider) (*Registry, error) {
	if current == nil {
		return nil, errors.New("kms: a current provider is required")
	}
	r := &Registry{current: current, byName: map[string]Provider{}}
	for _, p := range append([]Provider{current}, others...) {
		if p == nil || p.Name() == "" {
			return nil, errors.New("kms: a provider is nil or has no name")
		}
		if _, dup := r.byName[p.Name()]; dup {
			return nil, fmt.Errorf("kms: provider %q is registered twice", p.Name())
		}
		r.byName[p.Name()] = p
		r.nameOrder = append(r.nameOrder, p.Name())
	}
	slices.Sort(r.nameOrder)
	return r, nil
}

// Current returns the provider that wraps new keys.
func (r *Registry) Current() Provider { return r.current }

// Lookup returns the provider named name. A provider that is not configured is an error of kind
// NotConfigured, never a silent pass.
func (r *Registry) Lookup(name string) (Provider, error) {
	p, ok := r.byName[name]
	if !ok {
		return nil, New(NotConfigured, "", "lookup", "the provider that wrapped this key is not configured")
	}
	return p, nil
}

// Names returns every configured provider name, sorted.
func (r *Registry) Names() []string { return slices.Clone(r.nameOrder) }

// Unwrap routes w to the provider that made it.
func (r *Registry) Unwrap(ctx context.Context, w Wrapped, aad []byte) ([]byte, error) {
	p, err := r.Lookup(w.Provider)
	if err != nil {
		return nil, err
	}
	return p.Unwrap(ctx, w, aad)
}
