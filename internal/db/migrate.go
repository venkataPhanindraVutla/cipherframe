package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// riverLockKey is the Postgres advisory lock key that serialises River's schema migration. It is
// distinct from the key goose uses for its own session lock.
const riverLockKey int64 = 0x6369706872667200 // "ciphrfr\0"

// Migrate brings the database fully up to date in one call: first Cipherframe's goose migrations,
// then River's own schema through its migrator (ADR 0007). River's migrations are pinned by the
// version of the River module in go.mod. Both steps are idempotent, and each runs under a Postgres
// advisory lock, so several instances may start at once.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if err := migrateGoose(ctx, pool); err != nil {
		return err
	}
	return migrateRiver(ctx, pool)
}

func migrateGoose(ctx context.Context, pool *pgxpool.Pool) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("db: migrations: %w", err)
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("db: migrations lock: %w", err)
	}
	// Closing the sql.DB releases its connections to the pool; it does not close the pool.
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer func() { _ = sqlDB.Close() }()

	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, sub, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("db: migrations provider: %w", mapError(err))
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("db: apply migrations: %w", mapError(err))
	}
	return nil
}

// riverLockPoll is how often a caller waiting for the River migration lock tries again.
const riverLockPoll = 250 * time.Millisecond

// migrateRiver applies River's schema with River's own Migrate (which may split migrations across
// transactions) while holding a session advisory lock. Waiting callers poll the lock with
// pg_try_advisory_lock and hand their connection back between attempts, so they never sit on
// pool connections that the lock holder's migrator needs. Holding a lock connection plus
// migrating needs a pool of at least two connections.
func migrateRiver(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := acquireRiverLock(ctx, pool)
	if err != nil {
		return err
	}
	defer func() {
		// The caller's context may be cancelled; the lock must still be released.
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", riverLockKey)
		conn.Release()
	}()

	migrator, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return fmt.Errorf("db: river migrator: %w", mapError(err))
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("db: apply river migrations: %w", mapError(err))
	}
	return nil
}

// acquireRiverLock returns a connection that holds the River migration lock.
func acquireRiverLock(ctx context.Context, pool *pgxpool.Pool) (*pgxpool.Conn, error) {
	for {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			return nil, fmt.Errorf("db: river migrations: %w", mapError(err))
		}
		var locked bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", riverLockKey).Scan(&locked); err != nil {
			conn.Release()
			return nil, fmt.Errorf("db: river migrations lock: %w", mapError(err))
		}
		if locked {
			return conn, nil
		}
		conn.Release()
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("db: river migrations lock: %w", mapError(ctx.Err()))
		case <-time.After(riverLockPoll):
		}
	}
}

// MapError classifies a driver error as an *errs.Error (ADR 0012) exactly as the repositories do.
// Other packages that run queries against the same database use it so that an unknown failure is
// never reported as "not found".
func MapError(err error) error { return mapError(err) }
