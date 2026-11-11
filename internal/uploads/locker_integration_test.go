//go:build integration

package uploads_test

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tus/tusd/v2/pkg/handler"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }

func lockCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// Two lockers stand for two edge replicas: they share only the database.
func TestLockerExcludesAcrossReplicas(t *testing.T) {
	pool := dbtest.NewMigrated(t)
	a, b := uploads.NewLocker(pool), uploads.NewLocker(pool)

	la, err := a.NewLock("ast_one")
	if err != nil {
		t.Fatal(err)
	}
	if err := la.Lock(lockCtx(t, 5*time.Second), func() { t.Error("the other replica cannot be asked to release") }); err != nil {
		t.Fatal(err)
	}

	// Another upload is not blocked.
	other, _ := b.NewLock("ast_two")
	if err := other.Lock(lockCtx(t, 5*time.Second), func() {}); err != nil {
		t.Fatalf("a lock on another upload: %v", err)
	}
	if err := other.Unlock(); err != nil {
		t.Fatal(err)
	}

	// The same upload on the other replica waits, then times out with tusd's lock error.
	lb, _ := b.NewLock("ast_one")
	start := time.Now()
	err = lb.Lock(lockCtx(t, 600*time.Millisecond), func() {})
	if !errors.Is(err, handler.ErrLockTimeout) {
		t.Fatalf("err = %v, want tusd's lock timeout", err)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Fatal("the second replica did not wait for the holder")
	}

	// Once released it can take over.
	acquired := make(chan error, 1)
	lb2, _ := b.NewLock("ast_one")
	go func() { acquired <- lb2.Lock(lockCtx(t, 10*time.Second), func() {}) }()
	time.Sleep(300 * time.Millisecond)
	if err := la.Unlock(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("after the release: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the lock was not handed over")
	}
	if err := lb2.Unlock(); err != nil {
		t.Fatal(err)
	}
}

// Within one process the holder is asked to release, which is how a client that reconnects takes
// over from a request the server has not yet noticed is dead.
func TestLockerAsksTheLocalHolderToRelease(t *testing.T) {
	pool := dbtest.NewMigrated(t)
	l := uploads.NewLocker(pool)

	holder, _ := l.NewLock("ast_x")
	var asked atomic.Bool
	released := make(chan struct{})
	if err := holder.Lock(lockCtx(t, 5*time.Second), func() {
		asked.Store(true)
		go func() { _ = holder.Unlock(); close(released) }()
	}); err != nil {
		t.Fatal(err)
	}
	next, _ := l.NewLock("ast_x")
	if err := next.Lock(lockCtx(t, 10*time.Second), func() {}); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	<-released
	if !asked.Load() {
		t.Fatal("the holder was not asked to release")
	}
	if err := next.Unlock(); err != nil {
		t.Fatal(err)
	}
}

func TestLockerUnlockIsSafeToRepeat(t *testing.T) {
	pool := dbtest.NewMigrated(t)
	l := uploads.NewLocker(pool)
	lk, _ := l.NewLock("ast_y")
	if err := lk.Lock(lockCtx(t, 5*time.Second), func() {}); err != nil {
		t.Fatal(err)
	}
	if err := lk.Unlock(); err != nil {
		t.Fatal(err)
	}
	if err := lk.Unlock(); err != nil {
		t.Fatalf("a second Unlock: %v", err)
	}
	// The connection went back to the pool without a lock: a fresh lock is immediate.
	again, _ := l.NewLock("ast_y")
	if err := again.Lock(lockCtx(t, 2*time.Second), func() {}); err != nil {
		t.Fatal(err)
	}
	_ = again.Unlock()
}
