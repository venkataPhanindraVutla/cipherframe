package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

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

// migrateRiver applies River's schema. The advisory lock is session-scoped, so it is taken and
// released on one dedicated connection.
func migrateRiver(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("db: river migrations: %w", mapError(err))
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", riverLockKey); err != nil {
		return fmt.Errorf("db: river migrations lock: %w", mapError(err))
	}
	defer func() {
		// The caller's context may be cancelled; the lock must still be released.
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", riverLockKey)
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

// MapError classifies a driver error as an *errs.Error (ADR 0012) exactly as the repositories do.
// Other packages that run queries against the same database use it so that an unknown failure is
// never reported as "not found".
func MapError(err error) error { return mapError(err) }
