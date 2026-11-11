package pipeline

import (
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
	renditions := media.Ladder(info)
	if len(renditions) == 0 {
		return permanent(FailureInvalidMedia, errors.New("no renditions can be made from the file"))
	}

	// 3. The content key: created once, here, before any rendition exists, and reused by a retry.
	ck, err := p.Keys.Ensure(ctx, asset.TenantID, asset.ID)
	if err != nil {
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
	spec := media.TranscodeSpec{Source: srcPath, OutDir: outDir, Info: info, Renditions: renditions}
	if err := p.transcode(ctx, asset, spec, log); err != nil {
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

	// 6. Encrypt, upload and write the canonical playlists.
	pub, err := p.publish(ctx, asset, key, outs, info, log)
	if err != nil {
		return err
	}

	// 7. Register everything and finish, atomically.
	summary, err := json.Marshal(pub.summary)
	if err != nil {
		return err
	}
	_, err = p.Repo.Complete(ctx, asset.TenantID, asset.ID, pub.artifacts, db.Completion{
		Duration: pub.duration, Renditions: summary, At: p.Now().UTC(),
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

// transcode runs FFmpeg under the transcode timeout and reports progress.
func (p *Processor) transcode(ctx context.Context, asset db.Asset, spec media.TranscodeSpec, log *slog.Logger) error {
	rep := startReporter(ctx, p.ProgressInterval, func(ctx context.Context, percent int) error {
		return p.Repo.SetProgress(ctx, asset.TenantID, asset.ID, percent)
	})
	defer rep.stop()

	t0 := p.Now()
	tctx, cancel := context.WithTimeout(ctx, p.TranscodeTimeout)
	defer cancel()
	err := p.Tools.Transcode(tctx, spec, func(done time.Duration) { rep.transcoded(done, spec.Info.Duration) })
	if err == nil {
		log.InfoContext(ctx, "transcoded", slog.Int("renditions", len(spec.Renditions)), slog.Duration("elapsed", p.Now().Sub(t0)))
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
