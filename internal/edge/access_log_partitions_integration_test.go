//go:build integration

package edge_test

import (
	"context"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
)

// The edge role's sweeper keeps the partitions of the current and the next two months, and never
// drops any.
func TestSweeperCreatesAccessLogPartitionsAhead(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		playback.RunSweeper(ctx, e.repos, time.Hour, e.log)
	}()
	count := func() int {
		var n int
		if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM pg_inherits WHERE inhparent = 'playback_access_log'::regclass").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	deadline := time.Now().Add(10 * time.Second)
	for count() < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if n := count(); n != 3 {
		t.Fatalf("%d partitions after the sweeper ran, want 3 (current month and two more)", n)
	}
	now := time.Now().UTC()
	for i := range 3 {
		name := "playback_access_log_p" + time.Date(now.Year(), now.Month()+time.Month(i), 1, 0, 0, 0, 0, time.UTC).Format("200601")
		var ok bool
		if err := e.pool.QueryRow(context.Background(), "SELECT to_regclass($1) IS NOT NULL", name).Scan(&ok); err != nil || !ok {
			t.Fatalf("partition %s missing (%v)", name, err)
		}
	}
	// A second run creates nothing and drops nothing.
	if n, err := playback.EnsureAccessLogPartitions(context.Background(), e.repos, now); err != nil || n != 0 {
		t.Fatalf("second ensure = %d, %v", n, err)
	}
	if count() != 3 {
		t.Fatal("partition count changed")
	}
}
