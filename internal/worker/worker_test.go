package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRunner struct {
	started, stopped atomic.Bool
	startErr         error
}

func (f *fakeRunner) Start(context.Context) error { f.started.Store(true); return f.startErr }
func (f *fakeRunner) Stop(context.Context) error  { f.stopped.Store(true); return nil }

func runFor(t *testing.T, w *Worker) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop")
		return nil
	}
}

func TestIdleWithoutKinds(t *testing.T) {
	f := &fakeRunner{}
	if err := runFor(t, New(nil, f, nil)); err != nil {
		t.Fatal(err)
	}
	if f.started.Load() {
		t.Fatal("queue must not start without kinds")
	}
}

func TestRunsQueueWithKinds(t *testing.T) {
	f := &fakeRunner{}
	if err := runFor(t, New(nil, f, []string{"example"})); err != nil {
		t.Fatal(err)
	}
	if !f.started.Load() || !f.stopped.Load() {
		t.Fatal("queue must start and stop")
	}
}

func TestStartFailureIsReturned(t *testing.T) {
	boom := errors.New("boom")
	err := New(nil, &fakeRunner{startErr: boom}, []string{"example"}).Run(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}
