// Package db is Cipherframe's datastore layer (ADR 0007): connection pool, embedded goose
// migrations, a server-version check (ADR 0017) and repositories over sqlc-generated queries.
//
// Repositories convert between database UUIDs and the typed IDs of package id, and return
// *errs.Error values (ADR 0012). Every tenant-scoped read takes the tenant ID and filters by it.
// Nothing in this package logs, and no error it returns contains the database URL.
package db

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// MinServerMajor is the oldest supported PostgreSQL major version (ADR 0017).
const MinServerMajor = 16

// ErrUnsupportedServer is returned (wrapped) by CheckServerVersion when PostgreSQL is older than
// MinServerMajor or its version cannot be understood. Unknown versions fail closed.
var ErrUnsupportedServer = errors.New("db: unsupported PostgreSQL server version")

// Open creates a connection pool from cfg.DatabaseURL and verifies it with a ping. The URL is
// revealed only here, and no returned error contains it or any text derived from it.
func Open(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	return OpenSized(ctx, cfg, 0)
}

// OpenSized is Open with a cap on the pool's connections; zero keeps the driver default. The edge
// uses a second, larger pool for the advisory locks that tus uploads hold on a connection for as
// long as a request lasts, so uploads cannot starve ordinary queries.
func OpenSized(ctx context.Context, cfg *config.Config, maxConns int32) (*pgxpool.Pool, error) {
	if cfg == nil || cfg.DatabaseURL.IsEmpty() {
		return nil, errs.New(errs.InternalError, "database is not configured")
	}
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL.Reveal())
	if err != nil {
		// pgx parse errors can quote parts of the URL; drop the text entirely.
		return nil, errs.Wrap(errs.InternalError, "database URL is invalid",
			errors.New("db: database URL could not be parsed"))
	}
	if maxConns > 0 {
		poolCfg.MaxConns = maxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, sanitizedConnectError(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, sanitizedConnectError(err)
	}
	return pool, nil
}

// sanitizedConnectError classifies err like mapError but replaces the cause with a fixed
// message, because connection errors can carry host and user names.
func sanitizedConnectError(err error) error {
	mapped := mapError(err)
	var e *errs.Error
	if errors.As(mapped, &e) {
		return errs.Wrap(e.Code, e.Detail, errors.New("db: could not connect to the database"))
	}
	return errs.Wrap(errs.DependencyUnavailable, "database unavailable",
		errors.New("db: could not connect to the database"))
}

// CheckServerVersion refuses to run against PostgreSQL older than MinServerMajor.
func CheckServerVersion(ctx context.Context, pool *pgxpool.Pool) error {
	var v string
	if err := pool.QueryRow(ctx, "SHOW server_version").Scan(&v); err != nil {
		return fmt.Errorf("db: read server version: %w", mapError(err))
	}
	return checkVersion(v)
}

func checkVersion(v string) error {
	major, err := parseMajor(v)
	if err != nil {
		return fmt.Errorf("%w: cannot read version", ErrUnsupportedServer)
	}
	if major < MinServerMajor {
		return fmt.Errorf("%w: found %d, need %d or newer", ErrUnsupportedServer, major, MinServerMajor)
	}
	return nil
}

// parseMajor extracts the major version from a server_version string such as "16.15",
// "18.6 (Debian 18.6-1.pgdg13+1)", "17beta1" or "9.6.24".
func parseMajor(v string) (int, error) {
	v = strings.TrimSpace(v)
	end := 0
	for end < len(v) && v[end] >= '0' && v[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, errors.New("no leading digits")
	}
	return strconv.Atoi(v[:end])
}
