package uploads

import (
	"context"
	"hash/fnv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tus/tusd/v2/pkg/handler"
	"github.com/tus/tusd/v2/pkg/memorylocker"
)

// Locker is a tusd locker that works across several edge replicas. tusd needs exactly one
// request at a time to write to an upload, because it computes offsets and parts from what the
// object store holds. Locker takes two locks:
//
//   - an in-process lock (tusd's memory locker), which keeps tusd's handshake: a request that finds
//     the upload busy asks the holder to release it, which is how a client that reconnects after a
//     dropped connection takes over from the request the server has not noticed is dead;
//   - a Postgres session-level advisory lock, which excludes requests on other replicas. These are
//     polled, not signalled: a request for an upload held by another replica waits until the holder
//     finishes or its own deadline (tusd's AcquireLockTimeout) passes, then fails with a lock
//     timeout the client may retry.
//
// The advisory lock lives on a connection that the lock holds for its whole life, so Locker needs
// a pool of its own, separate from the one that serves queries, or active uploads could starve
// authentication.
type Locker struct {
	pool *pgxpool.Pool
	mem  *memorylocker.MemoryLocker
	poll time.Duration
}

// NewLocker returns a Locker over pool, which should be dedicated to locks.
func NewLocker(pool *pgxpool.Pool) *Locker {
	return &Locker{pool: pool, mem: memorylocker.New(), poll: 100 * time.Millisecond}
}

var _ handler.Locker = (*Locker)(nil)

// UseIn registers the locker in a tusd composer.
func (l *Locker) UseIn(c *handler.StoreComposer) { c.UseLocker(l) }

// advisoryKey maps an upload ID to a 64-bit advisory lock key. Two uploads that collide merely
// serialise; they never share data.
func advisoryKey(uploadID string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("cipherframe/tus/" + uploadID))
	return int64(h.Sum64()) //nolint:gosec // wrapping is intended: any 64-bit pattern is a valid key
}

// NewLock implements handler.Locker.
func (l *Locker) NewLock(uploadID string) (handler.Lock, error) {
	mem, err := l.mem.NewLock(uploadID)
	if err != nil {
		return nil, err
	}
	return &pgLock{l: l, mem: mem, key: advisoryKey(uploadID)}, nil
}

type pgLock struct {
	l   *Locker
	mem handler.Lock
	key int64

	mu   sync.Mutex
	conn *pgxpool.Conn
}

// Lock implements handler.Lock.
func (p *pgLock) Lock(ctx context.Context, requestUnlock func()) error {
	if err := p.mem.Lock(ctx, requestUnlock); err != nil {
		return err
	}
	conn, err := p.l.pool.Acquire(ctx)
	if err != nil {
		_ = p.mem.Unlock()
		return handler.ErrLockTimeout
	}
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		var got bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", p.key).Scan(&got); err != nil {
			conn.Release()
			_ = p.mem.Unlock()
			if ctx.Err() != nil {
				return handler.ErrLockTimeout
			}
			return err
		}
		if got {
			p.mu.Lock()
			p.conn = conn
			p.mu.Unlock()
			return nil
		}
		t.Reset(p.l.poll)
		select {
		case <-ctx.Done():
			conn.Release()
			_ = p.mem.Unlock()
			return handler.ErrLockTimeout
		case <-t.C:
		}
	}
}

// Unlock implements handler.Lock. If the advisory lock cannot be released cleanly the connection
// is closed, which releases every session lock it holds.
func (p *pgLock) Unlock() error {
	p.mu.Lock()
	conn := p.conn
	p.conn = nil
	p.mu.Unlock()
	if conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var ok bool
		if err := conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", p.key).Scan(&ok); err != nil || !ok {
			_ = conn.Conn().Close(ctx)
		}
		conn.Release()
	}
	return p.mem.Unlock()
}
