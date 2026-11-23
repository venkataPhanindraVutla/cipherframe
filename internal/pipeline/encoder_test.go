package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
)

// hwTools is the fake toolchain with a hardware encoder that fails the way a broken device does.
type hwTools struct {
	*fakeTools
	hwErr error
	used  []media.Encoder
}

func (h *hwTools) Transcode(ctx context.Context, spec media.TranscodeSpec, progress func(time.Duration)) error {
	h.used = append(h.used, spec.Encoder)
	if spec.Encoder.Hardware() && h.hwErr != nil {
		return h.hwErr
	}
	return h.fakeTools.Transcode(ctx, spec, progress)
}

func hardwareHarness(t *testing.T, hwErr error) (*harness, *hwTools) {
	t.Helper()
	h := newHarness(t)
	tools := &hwTools{fakeTools: h.tools, hwErr: hwErr}
	h.proc.Tools, h.proc.Encoder, h.proc.HWDevice = tools, media.EncoderNVENC, "/dev/dri/renderD129"
	return h, tools
}

func TestHardwareEncodeFailureRetriesWithSoftware(t *testing.T) {
	cause := errs.Wrap(errs.InvalidRequest, "The media file could not be transcoded.", errors.New("ffmpeg exited with code 1: Cannot open /dev/dri/renderD129"))
	h, tools := hardwareHarness(t, cause)
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	if got := h.repo.snapshot().State; got != db.AssetReady {
		t.Fatalf("state = %s, want ready: the fallback must finish the job", got)
	}
	if len(tools.used) != 2 || tools.used[0] != media.EncoderNVENC || tools.used[1] != media.EncoderSoftware {
		t.Fatalf("encoders used = %v, want [nvenc software]", tools.used)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "hardware encode failed; retrying with software") || !strings.Contains(logs, `"encoder":"nvenc"`) {
		t.Errorf("the fallback is not logged with the encoder's name:\n%s", logs)
	}
	if strings.Contains(logs, "renderD129") {
		t.Errorf("the log names the device:\n%s", logs)
	}
}

func TestHardwareEncodeSuccessIsNotRetried(t *testing.T) {
	h, tools := hardwareHarness(t, nil)
	if err := h.run(1, 5); err != nil {
		t.Fatal(err)
	}
	if len(tools.used) != 1 || tools.used[0] != media.EncoderNVENC {
		t.Fatalf("encoders used = %v, want [nvenc]", tools.used)
	}
	if tools.lastSpec.HWDevice != "/dev/dri/renderD129" {
		t.Errorf("the device did not reach the transcode: %q", tools.lastSpec.HWDevice)
	}
}

func TestHardwareTimeoutIsNotRetried(t *testing.T) {
	h, tools := hardwareHarness(t, errs.Wrap(errs.Timeout, "Transcoding took too long.", errors.New("deadline")))
	if err := h.run(1, 1); err == nil {
		t.Fatal("expected the timeout to fail the job")
	}
	if len(tools.used) != 1 {
		t.Fatalf("a timeout ran %d transcodes, want 1", len(tools.used))
	}
}

func TestSoftwareFailureIsNotRetried(t *testing.T) {
	h := newHarness(t)
	h.tools.transcodeErr = errs.Wrap(errs.InvalidRequest, "The media file could not be transcoded.", errors.New("bad"))
	if err := h.run(1, 1); err == nil {
		t.Fatal("expected a failure")
	}
	if h.tools.transcodes != 1 {
		t.Fatalf("software ran %d transcodes, want 1", h.tools.transcodes)
	}
}
