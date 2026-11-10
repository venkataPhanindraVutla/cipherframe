// Package health runs readiness checks (ADR 0015). A Checker tests one dependency; a Runner runs
// a fixed set of checkers concurrently, each under its own timeout, and reduces them to a Report
// that carries check names and pass/fail only. No error text, host name or credential ever leaves
// this package in a Report, because /readyz is unauthenticated.
//
// Queue seam (ADR 0007, ADR 0010): the job-queue task adds a Checker named "queue" and passes it
// to the extra-checkers parameter of server.Run (internal/server). Nothing else changes, because
// /readyz reports whatever checkers the Runner holds.
package health

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// DefaultTimeout is the per-check timeout used when none is given.
const DefaultTimeout = 2 * time.Second

// Checker tests one dependency.
type Checker interface {
	// Name is a fixed, human-readable identifier such as "database". It appears in the public
	// readiness response, so it must not contain host names or other deployment detail.
	Name() string
	// Check returns nil when the dependency is usable. It must honour ctx.
	Check(ctx context.Context) error
}

// Func adapts a function to a Checker.
func Func(name string, fn func(context.Context) error) Checker { return funcChecker{name, fn} }

type funcChecker struct {
	name string
	fn   func(context.Context) error
}

func (f funcChecker) Name() string                    { return f.name }
func (f funcChecker) Check(ctx context.Context) error { return f.fn(ctx) }

// Result is the outcome of one check.
type Result struct {
	Name string
	OK   bool
}

// Report is the outcome of a Runner run. Results are sorted by name.
type Report struct {
	OK      bool
	Results []Result
}

// Runner runs checkers.
type Runner struct {
	checkers []Checker
	timeout  time.Duration
	log      *slog.Logger
}

// NewRunner returns a Runner. A non-positive timeout means DefaultTimeout. A nil log discards
// failure logs. The checkers are fixed for the Runner's lifetime.
func NewRunner(log *slog.Logger, timeout time.Duration, checkers ...Checker) *Runner {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Runner{checkers: append([]Checker(nil), checkers...), timeout: timeout, log: log}
}

// Run executes every checker concurrently. A checker that returns an error, panics or does not
// finish within the timeout counts as failed; its error text is not logged (it may name hosts),
// only that it failed and whether it timed out. With no checkers the report is OK.
func (r *Runner) Run(ctx context.Context) Report {
	results := make([]Result, len(r.checkers))
	var wg sync.WaitGroup
	for i, c := range r.checkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = r.runOne(ctx, c)
		}()
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	rep := Report{OK: true, Results: results}
	for _, res := range results {
		if !res.OK {
			rep.OK = false
		}
	}
	return rep
}

func (r *Runner) runOne(ctx context.Context, c Checker) Result {
	name := c.Name()
	cctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	done := make(chan error, 1) // buffered: a checker that ignores ctx must not leak a blocked send
	go func() {
		defer func() {
			if v := recover(); v != nil {
				done <- errPanicked
			}
		}()
		done <- c.Check(cctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			r.log.LogAttrs(ctx, slog.LevelWarn, "readiness check failed", slog.String("check", name))
			return Result{Name: name}
		}
		return Result{Name: name, OK: true}
	case <-cctx.Done():
		r.log.LogAttrs(ctx, slog.LevelWarn, "readiness check failed",
			slog.String("check", name), slog.Bool("timed_out", true))
		return Result{Name: name}
	}
}

type panicked struct{}

func (panicked) Error() string { return "health: checker panicked" }

var errPanicked error = panicked{}
