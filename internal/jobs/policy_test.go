package jobs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/riverqueue/river/rivertype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

func TestClassify(t *testing.T) {
	secret := "https://storage.invalid/obj?X-Signature=SECRET-TOKEN" //nolint:gosec // a fake value the test checks never leaks

	cases := []struct {
		name       string
		err        error
		wantCancel bool
		wantCode   string
	}{
		{"not found is final", errs.New(errs.NotFound, secret), true, "not_found"},
		{"invalid request is final", errs.New(errs.InvalidRequest, "x"), true, "invalid_request"},
		{"forbidden is final", errs.New(errs.Forbidden, "x"), true, "forbidden"},
		{"wrapped final error is final", fmt.Errorf("step: %w", errs.New(errs.Conflict, "x")), true, "conflict"},
		{"timeout retries", errs.New(errs.Timeout, "x"), false, "timeout"},
		{"dependency unavailable retries", errs.New(errs.DependencyUnavailable, "x"), false, "dependency_unavailable"},
		{"rate limited retries", errs.New(errs.RateLimited, "x"), false, "rate_limited"},
		{"unregistered code retries", errs.New(errs.Code("made_up"), "x"), false, "internal_error"},
		{"unknown error retries", errors.New(secret), false, "internal_error"},
		{"context deadline retries", context.DeadlineExceeded, false, "timeout"},
		// A registered code that is not marked retryable is final, even internal_error.
		{"explicit internal error is final", errs.New(errs.InternalError, "x"), true, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.err)
			var cancel *rivertype.JobCancelError
			isCancel := errors.As(got, &cancel)
			if isCancel != tc.wantCancel {
				t.Fatalf("cancelled = %v, want %v (%v)", isCancel, tc.wantCancel, got)
			}
			if c := codeFromStored(got.Error()); c != tc.wantCode {
				t.Fatalf("stored code = %q, want %q (error text %q)", c, tc.wantCode, got.Error())
			}
			if strings.Contains(got.Error(), "SECRET") || strings.Contains(got.Error(), "storage.invalid") {
				t.Fatalf("stored error text leaks the original error: %q", got.Error())
			}
		})
	}
}

func TestClassifyNilAndControlFlow(t *testing.T) {
	if classify(nil) != nil {
		t.Fatal("nil must stay nil")
	}
	snooze := Snooze(time.Minute)
	var s *rivertype.JobSnoozeError
	if !errors.As(classify(snooze), &s) || s.Duration != time.Minute {
		t.Fatalf("snooze must pass through, got %v", classify(snooze))
	}
	got := classify(Cancel(errs.New(errs.Forbidden, "x")))
	var c *rivertype.JobCancelError
	if !errors.As(got, &c) || codeFromStored(got.Error()) != "forbidden" {
		t.Fatalf("an explicit cancel keeps its code, got %v", got)
	}
}

func TestRetryable(t *testing.T) {
	if Retryable(errs.New(errs.NotFound, "x")) {
		t.Error("not_found must not be retryable")
	}
	if !Retryable(errs.New(errs.Timeout, "x")) {
		t.Error("timeout must be retryable")
	}
	if !Retryable(errors.New("boom")) {
		t.Error("an unknown error must be retried")
	}
}

func TestWorkerRecoversPanics(t *testing.T) {
	w := &worker[testArgs]{handler: func(context.Context, Job[testArgs]) error {
		panic("password=hunter2")
	}}
	err := w.Work(context.Background(), nil)
	if err == nil {
		t.Fatal("a panic must become an error")
	}
	if codeFromStored(err.Error()) != "internal_error" || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("panic error = %q", err.Error())
	}
}

type testArgs struct{ N int }

func (testArgs) Kind() string { return "test.job" }

func TestDefaultBackoff(t *testing.T) {
	want := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute}
	for i, w := range want {
		if got := DefaultBackoff(i + 1); got != w {
			t.Errorf("DefaultBackoff(%d) = %v, want %v", i+1, got, w)
		}
	}
	if got := DefaultBackoff(50); got != 30*time.Minute {
		t.Errorf("DefaultBackoff(50) = %v, want the 30 minute cap", got)
	}
}

func TestRegister(t *testing.T) {
	r := NewRegistry()
	h := func(context.Context, Job[testArgs]) error { return nil }
	if err := Register(r, h, KindConfig{}); err != nil {
		t.Fatal(err)
	}
	if got := r.config("test.job").MaxAttempts; got != DefaultMaxAttempts {
		t.Fatalf("default max attempts = %d, want %d", got, DefaultMaxAttempts)
	}
	if err := Register(r, h, KindConfig{}); err == nil {
		t.Fatal("registering a kind twice must fail")
	}
	if err := Register[testArgs](NewRegistry(), nil, KindConfig{}); err == nil {
		t.Fatal("a nil handler must be rejected")
	}
	r2 := NewRegistry()
	if err := Register(r2, h, KindConfig{MaxAttempts: 2}); err != nil {
		t.Fatal(err)
	}
	if got := r2.config("test.job").MaxAttempts; got != 2 {
		t.Fatalf("configured max attempts = %d, want 2", got)
	}
	if got := r2.config("unregistered.kind").MaxAttempts; got != DefaultMaxAttempts {
		t.Fatalf("unregistered kind max attempts = %d", got)
	}
}
