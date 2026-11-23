package pipeline

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/telemetry"
)

// FailureSourceMissing: the source object is gone from the source bucket.
const FailureSourceMissing = "source_missing"

// alignTolerance is how far apart two renditions' segment durations may be. They come from the same
// frames at the same constant frame rate, so any real difference is a whole frame or more.
const alignTolerance = 2 * time.Millisecond

// process runs every step for an asset that is in the processing state.
func (p *Processor) process(ctx context.Context, asset db.Asset, log *slog.Logger) error {
	// A retry starts clean: whatever an earlier attempt uploaded or registered is removed first,
	// so the result of this attempt is the whole truth about the asset's delivery objects.
	if err := p.cleanDelivery(ctx, asset); err != nil {
		return fmt.Errorf("pipeline: remove the previous attempt's output: %w", err)
	}
	if err := p.Repo.ResetProgress(ctx, asset.TenantID, asset.ID); err != nil {
		return err
	}

	// The job's private directory. It is removed whatever happens, which is what deletes the
	// plaintext segments; the base directory is 0700 and so is this one.
	dir, err := os.MkdirTemp(p.WorkDir, "job-")
	if err != nil {
		return fmt.Errorf("pipeline: create the job directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// The asset's brand logo is fixed now (ADR 0049) and kept for every retry and for the masked
	// variant, so a logo that changes while this runs does not reach this asset.
	logo, err := p.pinLogo(ctx, asset, dir)
	if err != nil {
		return err
	}

	// 1. Download and hash in one pass.
	if asset.SourceKey == "" {
		return permanent(FailureSourceMissing, errors.New("the asset has no source object"))
	}
	t0 := p.Now()
	srcPath := filepath.Join(dir, "source")
	src, storedSize, err := fetchSource(ctx, p.Source, asset.SourceKey, srcPath)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return permanent(FailureSourceMissing, err)
	case err != nil:
		return err
	case storedSize != asset.SizeBytes:
		return permanent(FailureSourceMismatch, errors.New("the stored source is not the size that was declared"))
	}
	if err := p.Repo.RecordSource(ctx, asset.TenantID, asset.ID, src.SHA256[:], src.Size); err != nil {
		return err
	}
	log.InfoContext(ctx, "source downloaded", slog.Int64("bytes", src.Size), slog.Duration("elapsed", p.Now().Sub(t0)))

	// 2. Probe and validate; pick the ladder.
	info, err := p.Tools.Probe(ctx, srcPath)
	if err != nil {
		return classifyMedia(err)
	}
	if err := media.Validate(info, p.Limits); err != nil {
		return classifyMedia(err)
	}
	renditions := media.Ladder(info, p.LadderHeights)
	if len(renditions) == 0 {
		return permanent(FailureInvalidMedia, errors.New("no renditions can be made from the file"))
	}
	if err := p.chargeQuota(ctx, asset, info.Duration); err != nil {
		return err
	}

	// 3. The content key: created once, here, before any rendition exists, and reused by a retry.
	ck, err := p.Keys.Ensure(ctx, asset.TenantID, asset.ID, keys.Original)
	if err != nil {
		if lerr := p.ensureLive(ctx, asset); lerr != nil {
			return lerr // the key was refused because deletion started
		}
		return err
	}
	defer ck.Zero()
	key := ck.Bytes()
	defer clear(key)

	// 4. One FFmpeg process for the whole ladder.
	outDir := filepath.Join(dir, "out")
	if err := os.Mkdir(outDir, 0o700); err != nil {
		return fmt.Errorf("pipeline: create the output directory: %w", err)
	}
	spec := media.TranscodeSpec{
		Source: srcPath, OutDir: outDir, Info: info, Renditions: renditions, Preset: p.X264Preset,
		Thumbs: thumbnailSpec(dir, info, renditions), Logo: logo.mediaSpec(),
	}
	encoder, err := p.transcode(ctx, asset, spec, true, log)
	if err != nil {
		return err
	}

	// 5. What FFmpeg wrote; the renditions must cut at the same places.
	outs := make([]media.RenditionOutput, 0, len(renditions))
	for _, r := range renditions {
		o, err := media.ReadRenditionOutput(spec.RenditionDir(r), r)
		if err != nil {
			return permanent(FailureTranscode, err)
		}
		outs = append(outs, o)
	}
	if err := media.CheckAligned(outs, alignTolerance); err != nil {
		return permanent(FailureTranscode, err)
	}

	// 5b. The extra codecs the tenant asked for when the asset was uploaded (ADR 0064), each in its
	// own run. One that cannot be made is recorded and the asset still becomes ready in H.264.
	extras, failed, err := p.extraCodecs(ctx, asset, srcPath, dir, info, logo, outs, log)
	if err != nil {
		return err
	}

	// 6. Encrypt, upload and write the canonical playlists, unless deletion started meanwhile.
	if err := p.ensureLive(ctx, asset); err != nil {
		return err
	}
	pub, err := p.publish(ctx, asset, keys.Original, key, withExtras(outs, extras), readThumbnails(spec, log), info, log)
	if err != nil {
		return err
	}

	// 7. Sign the manifest, then register everything and finish, atomically.
	summary, err := json.Marshal(pub.summary)
	if err != nil {
		return err
	}
	at := p.Now().UTC()
	sealed, err := p.sealManifest(ctx, asset, sourceDigest{sha256: src.SHA256, size: src.Size}, renditions, extras, info, pub, logo.manifestLogo(), encoder, at)
	if err != nil {
		return err
	}
	_, err = p.Repo.Complete(ctx, asset.TenantID, asset.ID, pub.artifacts, db.Completion{
		Duration: pub.duration, Renditions: summary, Manifest: sealed, ExtraCodecFailures: failed, At: at,
	})
	if errors.Is(err, db.ErrStateChanged) {
		// The asset left processing while we worked (deleted, say): do not leave its output behind.
		log.WarnContext(ctx, "the asset changed state during processing; removing the output")
		if cerr := p.cleanDelivery(context.WithoutCancel(ctx), asset); cerr != nil {
			return cerr
		}
		return nil
	}
	return err
}

// transcode runs FFmpeg under the transcode timeout and returns the encoder that produced the
// output. With track it reports progress on the asset; the masked variant does not, since it runs
// while the original owns the progress column.
//
// When a hardware encoder fails, the whole run is repeated once with libx264 (ADR 0066): one
// FFmpeg process makes every rendition, so a rendition's failure cannot be told apart from the
// others'. The fallback is counted, and logged with the encoder's name only.
func (p *Processor) transcode(ctx context.Context, asset db.Asset, spec media.TranscodeSpec, track bool, log *slog.Logger) (media.Encoder, error) {
	set := func(context.Context, int) error { return nil }
	if track {
		set = func(ctx context.Context, percent int) error {
			return p.Repo.SetProgress(ctx, asset.TenantID, asset.ID, percent)
		}
	}
	rep := startReporter(ctx, p.ProgressInterval, set)
	defer rep.stop()

	spec.Encoder, spec.HWDevice = cmp.Or(p.Encoder, media.EncoderSoftware), p.HWDevice
	err := p.runTranscode(ctx, spec, rep, log)
	if err != nil && spec.Encoder.Hardware() && ctx.Err() == nil && !isCode(err, errs.Timeout) {
		log.WarnContext(ctx, "hardware encode failed; retrying with software",
			slog.String("encoder", string(spec.Encoder)), slog.String("fallback", string(media.EncoderSoftware)))
		telemetry.EncoderFallback(string(spec.Encoder), telemetry.StageJob)
		spec.Encoder = media.EncoderSoftware
		if rerr := removeTranscodeOutput(spec); rerr != nil {
			return spec.Encoder, rerr
		}
		err = p.runTranscode(ctx, spec, rep, log)
	}
	return spec.Encoder, err
}

// removeTranscodeOutput clears what a failed run left, so the retry's files are the only ones.
func removeTranscodeOutput(spec media.TranscodeSpec) error {
	dirs := make([]string, 0, len(spec.Renditions)+1)
	for _, r := range spec.Renditions {
		dirs = append(dirs, spec.RenditionDir(r))
	}
	if spec.Thumbs != nil {
		dirs = append(dirs, spec.Thumbs.Dir)
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			return fmt.Errorf("pipeline: clear the failed transcode output: %w", err)
		}
	}
	return nil
}

// runTranscode is one FFmpeg run under the transcode timeout, with its errors classified.
func (p *Processor) runTranscode(ctx context.Context, spec media.TranscodeSpec, rep *reporter, log *slog.Logger) error {
	t0 := p.Now()
	tctx, cancel := context.WithTimeout(ctx, p.TranscodeTimeout)
	defer cancel()
	err := p.Tools.Transcode(tctx, spec, func(done time.Duration) { rep.transcoded(done, spec.Info.Duration) })
	if err == nil {
		log.InfoContext(ctx, "transcoded", slog.Int("renditions", len(spec.Renditions)),
			slog.String("encoder", string(spec.Encoder)), slog.Duration("elapsed", p.Now().Sub(t0)))
		return nil
	}
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case isCode(err, errs.Timeout):
		return permanent(FailureTranscodeTimeout, err)
	case isCode(err, errs.InvalidRequest):
		return permanent(FailureTranscode, err)
	}
	return err
}

// classifyMedia turns a probe or validation error into the right failure: a file that is not
// acceptable fails the asset for good, anything else (a timeout, FFprobe not running) is retried.
func classifyMedia(err error) error {
	if isCode(err, errs.InvalidRequest) {
		return permanent(FailureInvalidMedia, err)
	}
	return err
}
