package jobs

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
)

func TestKindQueue(t *testing.T) {
	h := func(context.Context, Job[testArgs]) error { return nil }
	r := NewRegistry()
	if err := Register(r, h, KindConfig{Queue: QueueMedia}); err != nil {
		t.Fatal(err)
	}
	if got := r.config("test.job").Queue; got != QueueMedia {
		t.Fatalf("registered queue = %q, want %q", got, QueueMedia)
	}
	if got := NewRegistry().config("test.job").Queue; got != "" {
		t.Fatalf("default queue = %q, want empty", got)
	}
	for _, bad := range []string{"Media", "has space", "-x", "x-", "a--b", strings.Repeat("a", 65), "media!"} {
		if err := Register(NewRegistry(), h, KindConfig{Queue: bad}); err == nil {
			t.Errorf("Register accepted queue name %q", bad)
		}
		if err := Declare[testArgs](NewRegistry(), KindConfig{Queue: bad}); err == nil {
			t.Errorf("Declare accepted queue name %q", bad)
		}
	}
	for _, ok := range []string{"media", "a", "high-prio_2", strings.Repeat("a", 64)} {
		if err := Register(NewRegistry(), h, KindConfig{Queue: ok}); err != nil {
			t.Errorf("Register rejected queue name %q: %v", ok, err)
		}
	}
}

func TestDeclareSuppliesQueueWithoutHandler(t *testing.T) {
	r := NewRegistry()
	if err := Declare[testArgs](r, KindConfig{Queue: QueueMedia}); err != nil {
		t.Fatal(err)
	}
	if got := r.config("test.job").Queue; got != QueueMedia {
		t.Fatalf("declared queue = %q, want %q", got, QueueMedia)
	}
	if k := r.Kinds(); len(k) != 0 {
		t.Fatalf("a declared kind must not count as handled, got %v", k)
	}
}

func TestNewQueueQueuesValidation(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/db")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for name, queues := range map[string]map[string]int{
		"zero count":     {QueueMedia: 0},
		"negative count": {QueueMedia: -1},
		"default queue":  {river.QueueDefault: 3},
		"bad name":       {"Media": 1},
	} {
		if _, err := NewQueue(pool, NewRegistry(), Config{Workers: 2, Queues: queues}); err == nil {
			t.Errorf("%s: NewQueue accepted Queues %v", name, queues)
		}
	}
	if _, err := NewQueue(pool, NewRegistry(), Config{Workers: 2, Queues: map[string]int{QueueMedia: 1}}); err != nil {
		t.Fatalf("valid Queues rejected: %v", err)
	}
	// Insert-only queues ignore Queues.
	if _, err := NewQueue(pool, NewRegistry(), Config{Queues: map[string]int{QueueMedia: 0}}); err != nil {
		t.Fatalf("insert-only queue must ignore Queues: %v", err)
	}
}
