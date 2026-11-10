// Command cipherframe-server runs the Cipherframe server roles (ADR 0008): api, edge and worker,
// alone or together. See docs/usage.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/server"
	"github.com/venkataPhanindraVutla/cipherframe/internal/version"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	cmd, err := server.ParseArgs(args)
	if err != nil {
		if errors.Is(err, server.ErrHelp) {
			fmt.Print(server.Usage)
			return 0
		}
		fmt.Fprintf(os.Stderr, "cipherframe-server: %v\n\n%s", err, server.Usage)
		return 2
	}

	// Configuration errors name variables, never values (ADR 0013).
	cfg, err := config.FromOS()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cipherframe-server: configuration: %v\n", err)
		return 2
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)

	// SIGINT and SIGTERM start a graceful shutdown. A second signal restores the default
	// behaviour (stop.Stop is called after the first), so a stuck shutdown can be interrupted.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); stop() }()

	info := version.Get()
	log.InfoContext(ctx, "starting", slog.String("version", info.Version), slog.String("commit", info.Commit))

	if cmd.MigrateOnly {
		err = server.Migrate(ctx, cfg, log)
	} else {
		err = server.Run(ctx, cfg, log, cmd.Options)
	}
	if err != nil {
		log.ErrorContext(context.Background(), "exiting with error", slog.String("error", err.Error()))
		return 1
	}
	return 0
}
