package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

// Bootstrap creates the first tenant, client and admin key in one transaction and writes the full
// key, and nothing else, to out (a line ending in a newline). Everything else is logged to log,
// which must not be out. The key is shown once; it is not stored.
func Bootstrap(ctx context.Context, cfg *config.Config, log *slog.Logger, out io.Writer, tenantName, clientName string) error {
	pool, err := openDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer pool.Close()

	res, err := auth.NewManager(pool, cfg.Peppers, nil).Bootstrap(ctx, tenantName, clientName)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	log.InfoContext(ctx, "bootstrap complete",
		slog.String("tenant_id", res.Tenant.ID.String()),
		slog.String("client_id", res.Client.ID.String()),
		slog.String("key_id", res.Key.ID.String()),
		slog.String("key_prefix", res.Key.Prefix),
		slog.Int("pepper_version", res.Key.PepperVersion),
	)
	if _, err := fmt.Fprintln(out, res.Secret.Reveal()); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

// PepperUsage prints, to out, how many active API keys reference each pepper version (ADR 0016):
// the numbers an operator needs to know when an old pepper can be removed.
func PepperUsage(ctx context.Context, cfg *config.Config, log *slog.Logger, out io.Writer) error {
	pool, err := openDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer pool.Close()

	usage, err := db.New(pool).CountAPIKeysByPepperVersion(ctx, time.Now())
	if err != nil {
		return fmt.Errorf("count keys by pepper version: %w", err)
	}
	current, _ := cfg.Peppers.Current()
	for _, line := range auth.PepperUsageLines(usage, cfg.Peppers.Versions(), current) {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return nil
}
