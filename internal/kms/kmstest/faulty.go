package kmstest

import (
	"context"
	"sync"

	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

// Faulty wraps a kms.Provider and injects failures, so tests can prove that callers fail closed
// when the key service is unavailable or a stored key fails authentication (M2-5). It adds no
// behaviour of its own while no fault is set. It is safe for concurrent use.
type Faulty struct {
	kms.Provider

	mu        sync.Mutex
	outage    bool
	integrity bool
	budget    int // remaining Wrap/Unwrap calls before an outage starts; negative means unlimited
	calls     int
}

// NewFaulty returns a Faulty over p with no fault set.
func NewFaulty(p kms.Provider) *Faulty { return &Faulty{Provider: p, budget: -1} }

// SetOutage makes every call fail with kms.ErrUnavailable until it is called with false.
func (f *Faulty) SetOutage(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outage = on
}

// SetIntegrityFailure makes Unwrap fail with kms.ErrInvalid (a wrapped key that fails
// authentication) until it is called with false. Wrap and Current are unaffected.
func (f *Faulty) SetIntegrityFailure(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.integrity = on
}

// FailAfter lets n more Wrap and Unwrap calls through and then starts an outage. A negative n
// removes the limit and, like SetOutage(false), ends any outage.
func (f *Faulty) FailAfter(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.budget = n
	if n < 0 {
		f.outage = false
	}
}

// Calls returns how many Wrap and Unwrap calls reached the wrapped provider.
func (f *Faulty) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *Faulty) down(op string, counted bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if counted && f.budget == 0 {
		f.outage = true
	}
	if f.outage {
		return kms.New(kms.Unavailable, f.Name(), op, "injected outage")
	}
	if counted {
		f.calls++
		if f.budget > 0 {
			f.budget--
		}
	}
	return nil
}

// Current implements kms.Provider.
func (f *Faulty) Current(ctx context.Context) (kms.KeyRef, error) {
	if err := f.down("current", false); err != nil {
		return kms.KeyRef{}, err
	}
	return f.Provider.Current(ctx)
}

// Wrap implements kms.Provider.
func (f *Faulty) Wrap(ctx context.Context, plaintext, aad []byte) (kms.Wrapped, error) {
	if err := f.down("wrap", true); err != nil {
		return kms.Wrapped{}, err
	}
	return f.Provider.Wrap(ctx, plaintext, aad)
}

// Unwrap implements kms.Provider.
func (f *Faulty) Unwrap(ctx context.Context, w kms.Wrapped, aad []byte) ([]byte, error) {
	if err := f.down("unwrap", true); err != nil {
		return nil, err
	}
	f.mu.Lock()
	integrity := f.integrity
	f.mu.Unlock()
	if integrity {
		return nil, kms.New(kms.Invalid, f.Name(), "unwrap", "injected authentication failure")
	}
	return f.Provider.Unwrap(ctx, w, aad)
}

// HasKEK forwards to the wrapped provider when it implements kms.KEKChecker, and otherwise reports
// true (a remote provider's versions are not known locally).
func (f *Faulty) HasKEK(ref kms.KeyRef) bool {
	if c, ok := f.Provider.(kms.KEKChecker); ok {
		return c.HasKEK(ref)
	}
	return true
}

var _ kms.Provider = (*Faulty)(nil)
