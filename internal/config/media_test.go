package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMediaDefaults(t *testing.T) {
	c, err := load(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := c.Media
	if m.FFmpegPath != "ffmpeg" || m.FFprobePath != "ffprobe" || m.MaxSourceDuration != 4*time.Hour ||
		m.MaxSourceWidth != 3840 || m.MaxSourceHeight != 2160 || m.TranscodeTimeout != 6*time.Hour || m.Concurrency != 1 || m.MaskTimeout != 2*time.Hour {
		t.Fatalf("unexpected media defaults: %+v", m)
	}
	if want := filepath.Join(os.TempDir(), "cipherframe"); m.WorkDir != want {
		t.Fatalf("default work dir = %q, want %q", m.WorkDir, want)
	}
}

func TestMediaOverrides(t *testing.T) {
	c, err := load(base.with(
		EnvFFmpegPath, "/opt/ff/ffmpeg", EnvFFprobePath, "/opt/ff/ffprobe",
		EnvMaxSourceDuration, "90m", EnvMaxSourceWidth, "1920", EnvMaxSourceHeight, "1080",
		EnvTranscodeTimeout, "2h30m", EnvWorkDir, "/var/lib/cipherframe/work/",
		EnvMediaConcurrency, "4", EnvMaskTimeout, "45m",
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := c.Media
	if m.FFmpegPath != "/opt/ff/ffmpeg" || m.FFprobePath != "/opt/ff/ffprobe" || m.MaxSourceDuration != 90*time.Minute ||
		m.MaxSourceWidth != 1920 || m.MaxSourceHeight != 1080 || m.TranscodeTimeout != 150*time.Minute ||
		m.WorkDir != "/var/lib/cipherframe/work" || m.Concurrency != 4 || m.MaskTimeout != 45*time.Minute {
		t.Fatalf("unexpected media config: %+v", m)
	}
}

func TestMediaInvalid(t *testing.T) {
	for _, kv := range [][2]string{
		{EnvFFmpegPath, "-i"},
		{EnvFFmpegPath, "ffmpeg\n"},
		{EnvFFprobePath, " ffprobe"},
		{EnvMaxSourceDuration, "0s"},
		{EnvMaxSourceDuration, "-1h"},
		{EnvMaxSourceDuration, "forever"},
		{EnvMaxSourceDuration, "9999h"},
		{EnvMaxSourceWidth, "0"},
		{EnvMaxSourceWidth, "abc"},
		{EnvMaxSourceHeight, "99999"},
		{EnvTranscodeTimeout, "0"},
		{EnvTranscodeTimeout, "1y"},
		{EnvMaskTimeout, "0"},
		{EnvMaskTimeout, "9999h"},
		{EnvMediaConcurrency, "0"},
		{EnvMediaConcurrency, "65"},
		{EnvMediaConcurrency, "-1"},
		{EnvMediaConcurrency, "two"},
		{EnvWorkDir, "relative/dir"},
		{EnvWorkDir, " /tmp/x"},
		{EnvWorkDir, "/tmp/x\ny"},
	} {
		_, err := load(base.with(kv[0], kv[1]), nil)
		if err == nil {
			t.Errorf("%s=%q: expected an error", kv[0], kv[1])
		} else if !strings.Contains(err.Error(), kv[0]) {
			t.Errorf("%s=%q: error does not name the variable: %v", kv[0], kv[1], err)
		}
	}
}
