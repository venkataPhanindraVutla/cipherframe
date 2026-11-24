package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/telemetry"
)

// extraRun is the output of one extra codec (ADR 0064): its full ladder, the encoder that made it
// (which can differ from the H.264 run's, after a hardware fallback or for AV1 under VideoToolbox) and
// what FFmpeg wrote.
type extraRun struct {
	codec   media.Codec
	encoder media.Encoder
	rends   []media.Rendition
	outs    []media.RenditionOutput
}

// extraCodecs makes the extra codecs the asset asked for (asset.ExtraCodecs, fixed when it was
// uploaded) from src, each in its own FFmpeg run beside the H.264 one (ADR 0067), and returns what was
// made and what was not. A codec that cannot be made is a recorded failure, never a failed asset: the
// H.264 ladder is complete and playable. Only an interrupted job (shutdown, deadline) gives an error,
// so the job is retried whole. base is the H.264 output the new renditions must align with.
//
// dir is the job's private directory (each run writes under it) and logo the brand logo to draw, which
// every rendition of every codec carries (ADR 0049). The poster and the sprite sheet are made once, by
// the H.264 run.
func (p *Processor) extraCodecs(ctx context.Context, asset db.Asset, src, dir string, info media.Info, logo *jobLogo, base []media.RenditionOutput, log *slog.Logger) ([]extraRun, []db.CodecFailure, error) {
	var runs []extraRun
	var failed []db.CodecFailure
	for _, c := range media.ExtraCodecs() {
		if !slices.Contains(asset.ExtraCodecs, string(c)) {
			continue
		}
		run, reason, err := p.extraCodec(ctx, asset, c, src, dir, info, logo, base, log)
		if err != nil {
			return nil, nil, err
		}
		if reason != "" {
			// The reason is a fixed code; the cause is in the log line extraCodec wrote.
			failed = append(failed, db.CodecFailure{Codec: string(c), Reason: reason})
			telemetry.ExtraCodecFailure(string(c), reason)
			continue
		}
		runs = append(runs, run)
	}
	return runs, failed, nil
}

// extraCodec makes one codec. It returns a failure reason (a db.Codec* code) when the codec could not
// be made, and an error only when the job was interrupted or the work directory cannot be used.
func (p *Processor) extraCodec(ctx context.Context, asset db.Asset, c media.Codec, src, dir string, info media.Info, logo *jobLogo, base []media.RenditionOutput, log *slog.Logger) (extraRun, string, error) {
	log = log.With(slog.String("codec", string(c)))
	if !slices.Contains(p.Codecs, c) {
		log.WarnContext(ctx, "extra codec skipped: this worker's FFmpeg has no encoder for it")
		return extraRun{}, db.CodecEncoderUnavailable, nil
	}
	rends := p.crf().Apply(media.LadderFor(c, info, p.LadderHeights))
	if len(rends) == 0 {
		return extraRun{}, db.CodecTranscodeFailed, nil
	}
	outDir := filepath.Join(dir, "out-"+string(c))
	if err := os.Mkdir(outDir, 0o700); err != nil {
		return extraRun{}, "", fmt.Errorf("pipeline: create the output directory: %w", err)
	}
	spec := media.TranscodeSpec{
		Source: src, OutDir: outDir, Info: info, Renditions: rends, Codec: c, Logo: logo.mediaSpec(),
		TSOffset: h264Start(ctx, base[0], log),
	}
	encoder, err := p.transcode(ctx, asset, spec, false, log)
	if err != nil {
		var perm *permanentError
		switch {
		case ctx.Err() != nil:
			return extraRun{}, "", ctx.Err()
		case errors.As(err, &perm) && perm.code == FailureTranscodeTimeout:
			log.WarnContext(ctx, "extra codec failed: the transcode timed out")
			return extraRun{}, db.CodecTranscodeTimeout, nil
		}
		log.WarnContext(ctx, "extra codec failed", slog.String("error", err.Error()))
		return extraRun{}, db.CodecTranscodeFailed, nil
	}

	outs := make([]media.RenditionOutput, 0, len(rends))
	for _, r := range rends {
		o, err := media.ReadRenditionOutput(spec.RenditionDir(r), r)
		if err != nil {
			log.WarnContext(ctx, "extra codec failed: unusable output", slog.String("error", err.Error()))
			return extraRun{}, db.CodecOutputInvalid, nil
		}
		// The codec string is read from the init segment before anything is published, so a codec
		// whose output cannot be described fails here and not halfway through publishing.
		init, err := os.ReadFile(o.InitPath) //nolint:gosec // a file FFmpeg wrote in the job's private directory
		if err != nil {
			return extraRun{}, "", fmt.Errorf("pipeline: read init segment: %w", err)
		}
		if _, err := codecString(init, info.Audio != nil); err != nil {
			log.WarnContext(ctx, "extra codec failed: unreadable codec configuration", slog.String("error", err.Error()))
			return extraRun{}, db.CodecOutputInvalid, nil
		}
		outs = append(outs, o)
	}
	// Every codec cuts at the same frames: same segment count and durations as the H.264 ladder.
	if err := media.CheckAligned(append([]media.RenditionOutput{base[0]}, outs...), alignTolerance); err != nil {
		log.WarnContext(ctx, "extra codec failed: not aligned with H.264", slog.String("error", err.Error()))
		return extraRun{}, db.CodecOutputInvalid, nil
	}
	return extraRun{codec: c, encoder: encoder, rends: rends, outs: outs}, "", nil
}

// h264Start is where the H.264 ladder presents its first picture: its encoder holds frames back for
// reordering, which puts the first picture at two frames in, and every codec is given the same start so
// all the renditions present at the same times (ADR 0067). It is zero, which changes nothing, when the
// segment cannot be read: the renditions then differ in start by the encoders' delay, a frame or two.
func h264Start(ctx context.Context, o media.RenditionOutput, log *slog.Logger) time.Duration {
	init, err := os.ReadFile(o.InitPath) //nolint:gosec // a file FFmpeg wrote in the job's private directory
	var seg []byte
	if err == nil {
		seg, err = os.ReadFile(o.Segments[0].Path) //nolint:gosec // as above
	}
	var start time.Duration
	if err == nil {
		start, err = media.FirstVideoPTS(init, seg)
	}
	if err != nil {
		log.WarnContext(ctx, "could not read where the H.264 rendition starts; the extra codec keeps its own start", slog.String("error", err.Error()))
		return 0
	}
	return start
}

// withExtras returns the outputs of the H.264 run followed by those of every extra codec, which is the
// order the renditions are published in. H.264 stays first.
func withExtras(base []media.RenditionOutput, extras []extraRun) []media.RenditionOutput {
	out := slices.Clone(base)
	for _, e := range extras {
		out = append(out, e.outs...)
	}
	return out
}

// extraRungs records the encoder settings of the extra codecs' renditions beside the H.264 rungs: the
// rung, the codec, the encoder that made it and its preset (only a software encoder has one).
func extraRungs(extras []extraRun) []manifest.Rung {
	var out []manifest.Rung
	for _, e := range extras {
		preset := ""
		if !e.encoder.For(e.codec).Hardware() {
			preset = map[media.Codec]string{media.CodecHEVC: media.X265Preset, media.CodecAV1: media.SVTAV1Preset}[e.codec]
		}
		for _, r := range e.rends {
			out = append(out, manifest.Rung{
				Name: r.Name, CRF: r.CRF, MaxrateKbps: r.MaxrateKbps, BufsizeKbps: r.BufsizeKbps, AudioKbps: r.AudioKbps,
				Codec: string(e.codec), VideoCodec: e.encoder.FFmpegName(e.codec), Preset: preset,
			})
		}
	}
	return out
}
