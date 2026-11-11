package server

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
)

func TestCheckMediaToolsRefusesMissingBinaries(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	cfg := &config.Config{Media: config.Media{FFmpegPath: missing, FFprobePath: missing}}
	err := checkMediaTools(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"worker:", config.EnvFFmpegPath, config.EnvFFprobePath} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestMediaToolsFollowConfig(t *testing.T) {
	cfg := &config.Config{Media: config.Media{FFmpegPath: "/x/ffmpeg", FFprobePath: "/x/ffprobe"}}
	if got := mediaTools(cfg); got.FFmpeg != "/x/ffmpeg" || got.FFprobe != "/x/ffprobe" {
		t.Fatalf("%+v", got)
	}
}
