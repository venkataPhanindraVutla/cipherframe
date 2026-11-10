package health

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
)

func ok(name string) Checker { return Func(name, func(context.Context) error { return nil }) }

func failing(name string) Checker {
	return Func(name, func(context.Context) error { return errors.New("dial tcp db.internal.example:5432: password=hunter2") })
}

func TestRunAggregation(t *testing.T) {
	var buf bytes.Buffer
	r := NewRunner(slog.New(slog.NewJSONHandler(&buf, nil)), time.Second, ok("b"), failing("a"), ok("c"))
	rep := r.Run(context.Background())
	if rep.OK {
		t.Fatal("report OK despite a failing check")
	}
	want := []Result{{"a", false}, {"b", true}, {"c", true}}
	if len(rep.Results) != 3 {
		t.Fatalf("results = %v", rep.Results)
	}
	for i, w := range want {
		if rep.Results[i] != w {
			t.Fatalf("result %d = %+v, want %+v (sorted by name)", i, rep.Results[i], w)
		}
	}
	if strings.Contains(buf.String(), "hunter2") || strings.Contains(buf.String(), "db.internal") {
		t.Fatalf("check error text was logged: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"check":"a"`) {
		t.Fatalf("failure not logged by name: %s", buf.String())
	}
}

func TestRunAllOKAndEmpty(t *testing.T) {
	if rep := NewRunner(nil, 0, ok("x"), ok("y")).Run(context.Background()); !rep.OK {
		t.Fatalf("expected OK: %+v", rep)
	}
	if rep := NewRunner(nil, 0).Run(context.Background()); !rep.OK || len(rep.Results) != 0 {
		t.Fatalf("empty runner: %+v", rep)
	}
}

func TestRunTimeoutDoesNotWaitForStuckChecker(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	stuck := Func("stuck", func(context.Context) error { <-release; return nil }) // ignores its context
	var buf bytes.Buffer
	r := NewRunner(slog.New(slog.NewJSONHandler(&buf, nil)), 50*time.Millisecond, stuck, ok("fine"))

	start := time.Now()
	rep := r.Run(context.Background())
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Run took %v; the per-check timeout was not enforced", d)
	}
	if rep.OK || rep.Results[0] != (Result{"fine", true}) || rep.Results[1] != (Result{"stuck", false}) {
		t.Fatalf("report = %+v", rep)
	}
	if !strings.Contains(buf.String(), `"timed_out":true`) {
		t.Fatalf("timeout not logged: %s", buf.String())
	}
}

func TestRunChecksRunConcurrentlyWithOwnDeadline(t *testing.T) {
	var sawDeadline bool
	c := Func("d", func(ctx context.Context) error {
		_, sawDeadline = ctx.Deadline()
		return nil
	})
	NewRunner(nil, time.Second, c).Run(context.Background())
	if !sawDeadline {
		t.Fatal("checker context has no deadline")
	}
}

func TestRunPanickingCheckerFails(t *testing.T) {
	rep := NewRunner(nil, time.Second, Func("p", func(context.Context) error { panic("boom") }), ok("q")).Run(context.Background())
	if rep.OK || rep.Results[0].OK || !rep.Results[1].OK {
		t.Fatalf("report = %+v", rep)
	}
}

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func TestDatabaseChecker(t *testing.T) {
	if c := Database(fakePinger{}); c.Name() != "database" || c.Check(context.Background()) != nil {
		t.Fatal("database check should pass")
	}
	if Database(fakePinger{errors.New("down")}).Check(context.Background()) == nil {
		t.Fatal("database check should fail")
	}
}

// headStore is a storage.Store whose Head returns a fixed error; other methods are unused.
type headStore struct {
	storage.Store
	err error
	key string
}

func (h *headStore) Head(_ context.Context, key string) (storage.ObjectInfo, error) {
	h.key = key
	return storage.ObjectInfo{}, h.err
}

func TestStorageChecker(t *testing.T) {
	cases := []struct {
		name string
		err  error
		ok   bool
	}{
		{"reachable, probe object absent", &storage.Error{Kind: storage.NotFound, Op: "head"}, true},
		{"reachable, object exists", nil, true},
		{"credentials refused", &storage.Error{Kind: storage.PermissionDenied, Op: "head"}, false},
		{"unavailable", &storage.Error{Kind: storage.Unavailable, Op: "head"}, false},
		{"timeout", &storage.Error{Kind: storage.Timeout, Op: "head"}, false},
		{"other", errors.New("???"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hs := &headStore{err: tc.err}
			c := Storage("storage_source", hs)
			if c.Name() != "storage_source" {
				t.Fatalf("name = %q", c.Name())
			}
			if got := c.Check(context.Background()) == nil; got != tc.ok {
				t.Fatalf("ok = %v, want %v", got, tc.ok)
			}
			if hs.key != ProbeKey {
				t.Fatalf("probed key %q", hs.key)
			}
		})
	}
}
