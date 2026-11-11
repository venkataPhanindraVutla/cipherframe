//go:build integration

// Package dbtest starts one Postgres container per test binary and hands out migrated databases,
// for integration tests outside internal/db. Use it from TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }
package dbtest

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

const defaultImage = "postgres:18.6"

var (
	adminURL string
	count    atomic.Int64
)

// Run starts the container (image from CIPHERFRAME_TEST_PG_IMAGE), runs m and stops it.
func Run(m *testing.M) int {
	image := os.Getenv("CIPHERFRAME_TEST_PG_IMAGE")
	if image == "" {
		image = defaultImage
	}
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, image,
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot start the test Postgres container:", err)
		return 1
	}
	defer func() { _ = testcontainers.TerminateContainer(ctr) }()
	adminURL, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read the container connection string:", err)
		return 1
	}
	return m.Run()
}

// NewMigrated creates an empty database in the container, applies all migrations and returns a
// pool on it.
func NewMigrated(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	defer admin.Close()
	name := fmt.Sprintf("d%d", count.Add(1))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}
