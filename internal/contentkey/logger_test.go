//go:build integration

package contentkey_test

import (
	"io"
	"log/slog"
)

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
