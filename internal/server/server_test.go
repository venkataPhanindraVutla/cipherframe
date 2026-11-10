package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRoles(t *testing.T) {
	good := map[string][]Role{
		"api":             {RoleAPI},
		"edge":            {RoleEdge},
		"worker":          {RoleWorker},
		"api,edge,worker": {RoleAPI, RoleEdge, RoleWorker},
		"worker, api":     {RoleWorker, RoleAPI},
	}
	for in, want := range good {
		got, err := ParseRoles(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("ParseRoles(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "  ", "bogus", "api,bogus", "api,api", "api,edge,api", "api,", ",api", "API", "api;edge"} {
		if got, err := ParseRoles(in); err == nil {
			t.Errorf("ParseRoles(%q) = %v, want an error", in, got)
		}
	}
}

func TestParseRolesErrorIsSafe(t *testing.T) {
	_, err := ParseRoles("bad\x1b[31m" + strings.Repeat("x", 100))
	if err == nil || strings.ContainsRune(err.Error(), 0x1b) || len(err.Error()) > 200 {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestParseArgs(t *testing.T) {
	c, err := ParseArgs([]string{"--role=api,edge", "--migrate"})
	if err != nil || c.MigrateOnly || !c.Options.Migrate || !slices.Equal(c.Options.Roles, []Role{RoleAPI, RoleEdge}) {
		t.Fatalf("got %+v, %v", c, err)
	}
	c, err = ParseArgs([]string{"-role", "worker"})
	if err != nil || c.Options.Migrate || !slices.Equal(c.Options.Roles, []Role{RoleWorker}) {
		t.Fatalf("migrate must default off: %+v, %v", c, err)
	}
	c, err = ParseArgs([]string{"migrate"})
	if err != nil || !c.MigrateOnly {
		t.Fatalf("migrate subcommand: %+v, %v", c, err)
	}
	if _, err = ParseArgs([]string{"--help"}); !errors.Is(err, ErrHelp) {
		t.Fatalf("help: %v", err)
	}
	for _, args := range [][]string{
		nil,
		{"--migrate"},
		{"--role=bogus"},
		{"--role=api,api"},
		{"--role=api", "extra"},
		{"--role=api", "--nope"},
		{"migrate", "--role=api"},
	} {
		if c, err := ParseArgs(args); err == nil {
			t.Errorf("ParseArgs(%v) = %+v, want an error", args, c)
		}
	}
}

type fakeService struct {
	err     error
	failNow bool
	stopped atomic.Bool
}

func (f *fakeService) run(ctx context.Context) error {
	if f.failNow {
		return f.err
	}
	<-ctx.Done()
	f.stopped.Store(true)
	return nil
}
func (*fakeService) close() {}

func TestRunServicesStopsOnContextCancel(t *testing.T) {
	a, b := &fakeService{}, &fakeService{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runServices(ctx, []service{a, b}) }()
	select {
	case err := <-done:
		t.Fatalf("returned before cancel: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("err = %v", err)
	}
	if !a.stopped.Load() || !b.stopped.Load() {
		t.Fatal("services were not stopped")
	}
}

func TestRunServicesFailureStopsTheOthers(t *testing.T) {
	boom := errors.New("boom")
	ok := &fakeService{}
	err := runServices(context.Background(), []service{ok, &fakeService{failNow: true, err: boom}})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if !ok.stopped.Load() {
		t.Fatal("the healthy service kept running after another failed")
	}
}

func TestHTTPServiceGracefulShutdown(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	started, release := make(chan struct{}), make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "finished")
	})
	svc, err := newHTTPService("api", "127.0.0.1:0", h, log)
	if err != nil {
		t.Fatal(err)
	}
	addr := svc.ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runServices(ctx, []service{svc}) }()

	body := make(chan string, 1)
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			body <- "error: " + err.Error()
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		body <- string(b)
	}()
	<-started
	cancel() // what SIGTERM does
	time.Sleep(100 * time.Millisecond)
	close(release)
	if got := <-body; got != "finished" {
		t.Fatalf("in-flight request was cut off: %q", got)
	}
	if err := <-done; err != nil {
		t.Fatalf("shutdown error: %v", err)
	}
	if c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", addr); err == nil {
		_ = c.Close()
		t.Fatal("still listening after shutdown")
	}
}

func TestNewHTTPServiceAddressInUse(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	first, err := newHTTPService("api", "127.0.0.1:0", http.NotFoundHandler(), log)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	if _, err := newHTTPService("edge", first.ln.Addr().String(), http.NotFoundHandler(), log); err == nil {
		t.Fatal("expected an address-in-use error")
	}
}
