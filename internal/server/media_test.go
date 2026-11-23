package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
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

// fakeEncodeFFmpeg is an "ffmpeg" that records its arguments and then succeeds or fails the way a
// broken device does, with the device in its message.
func fakeEncodeFFmpeg(t *testing.T, fail bool) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	bin, argsFile = filepath.Join(dir, "ffmpeg"), filepath.Join(dir, "args")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\n"
	if fail {
		script += "echo 'Cannot open /dev/dri/renderD128 (secret-device-detail)' >&2\nexit 1\n"
	}
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test fake must be executable
		t.Fatal(err)
	}
	return bin, argsFile
}

func TestSelectEncoderFallsBackToSoftware(t *testing.T) {
	bin, _ := fakeEncodeFFmpeg(t, true)
	cfg := &config.Config{Media: config.Media{FFmpegPath: bin, Encoder: media.EncoderVAAPI, HWDevice: media.DefaultHWDevice}}
	var logs bytes.Buffer
	selectEncoder(context.Background(), mediaTools(cfg), cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if cfg.Media.Encoder != media.EncoderSoftware {
		t.Fatalf("encoder = %q, want software", cfg.Media.Encoder)
	}
	out := logs.String()
	if strings.Count(out, "level=WARN") != 1 || !strings.Contains(out, "encoder=vaapi") {
		t.Errorf("want exactly one warning naming the encoder, got:\n%s", out)
	}
	if strings.Contains(out, "renderD128") || strings.Contains(out, "secret-device-detail") {
		t.Errorf("the warning leaks the device or FFmpeg's message:\n%s", out)
	}
}

func TestSelectEncoderKeepsAWorkingHardwareEncoder(t *testing.T) {
	bin, argsFile := fakeEncodeFFmpeg(t, false)
	cfg := &config.Config{Media: config.Media{FFmpegPath: bin, Encoder: media.EncoderNVENC, HWDevice: media.DefaultHWDevice}}
	selectEncoder(context.Background(), mediaTools(cfg), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if cfg.Media.Encoder != media.EncoderNVENC {
		t.Fatalf("encoder = %q, want nvenc", cfg.Media.Encoder)
	}
	if got, _ := os.ReadFile(argsFile); !strings.Contains(string(got), "h264_nvenc") {
		t.Errorf("the test encode did not use h264_nvenc: %s", got)
	}
}

func TestSelectEncoderLeavesSoftwareAlone(t *testing.T) {
	cfg := &config.Config{Media: config.Media{FFmpegPath: filepath.Join(t.TempDir(), "absent"), Encoder: media.EncoderSoftware}}
	selectEncoder(context.Background(), mediaTools(cfg), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if cfg.Media.Encoder != media.EncoderSoftware {
		t.Fatal("software must stay software and run no test encode")
	}
}
