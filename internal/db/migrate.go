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

// migrateRiver applies River's schema in one transaction on one connection: the transaction takes
// an advisory lock that Postgres releases at commit or rollback, and River's migrator runs on that
// same transaction. Nothing else is borrowed from the pool while the lock is held, so concurrent
// callers cannot exhaust a small pool and deadlock (a lock holder waiting for a connection that
// the lock waiters hold).
func migrateRiver(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: river migrations: %w", mapError(err))
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", riverLockKey); err != nil {
		return fmt.Errorf("db: river migrations lock: %w", mapError(err))
	}
	// A driver without a pool is enough for MigrateTx.
	migrator, err := rivermigrate.New(riverpgxv5.New(nil), nil)
	if err != nil {
		return fmt.Errorf("db: river migrator: %w", mapError(err))
	}
	if _, err := migrator.MigrateTx(ctx, tx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("db: apply river migrations: %w", mapError(err))
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: commit river migrations: %w", mapError(err))
	}
	return nil
}

// MapError classifies a driver error as an *errs.Error (ADR 0012) exactly as the repositories do.
// Other packages that run queries against the same database use it so that an unknown failure is
// never reported as "not found".
func MapError(err error) error { return mapError(err) }
