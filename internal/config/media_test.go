package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
)

func TestMediaDefaults(t *testing.T) {
	c, err := load(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := c.Media
	if m.FFmpegPath != "ffmpeg" || m.FFprobePath != "ffprobe" || m.MaxSourceDuration != 4*time.Hour ||
		m.MaxSourceWidth != 3840 || m.MaxSourceHeight != 2160 || m.TranscodeTimeout != 6*time.Hour || m.Concurrency != 1 || m.MaskTimeout != 2*time.Hour ||
		m.MaskConcurrency != 1 || m.LadderHeights != nil || m.X264Preset != "medium" {
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
		EnvMediaConcurrency, "4", EnvMaskTimeout, "45m", EnvMaskConcurrency, "3", EnvLadderHeights, "360, 720", EnvX264Preset, "veryfast",
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := c.Media
	if m.FFmpegPath != "/opt/ff/ffmpeg" || m.FFprobePath != "/opt/ff/ffprobe" || m.MaxSourceDuration != 90*time.Minute ||
		m.MaxSourceWidth != 1920 || m.MaxSourceHeight != 1080 || m.TranscodeTimeout != 150*time.Minute ||
		m.WorkDir != "/var/lib/cipherframe/work" || m.Concurrency != 4 || m.MaskTimeout != 45*time.Minute ||
		m.MaskConcurrency != 3 || !slices.Equal(m.LadderHeights, []int{720, 360}) || m.X264Preset != "veryfast" {
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
		{EnvMaskConcurrency, "0"},
		{EnvMaskConcurrency, "65"},
		{EnvMaskConcurrency, "many"},
		{EnvLadderHeights, ","},
		{EnvLadderHeights, "720,"},
		{EnvLadderHeights, "720,540"},
		{EnvLadderHeights, "720,720"},
		{EnvLadderHeights, "hd"},
		{EnvX264Preset, "fastest"},
		{EnvX264Preset, "Medium"},
		{EnvX264Preset, "placebo"},
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

func TestX264PresetAcceptsEveryPreset(t *testing.T) {
	for _, preset := range media.X264Presets() {
		c, err := load(base.with(EnvX264Preset, preset), nil)
		if err != nil || c.Media.X264Preset != preset {
			t.Errorf("%s=%q: got %q, %v", EnvX264Preset, preset, c.Media.X264Preset, err)
		}
	}
}
