// Package pipeline is the asset.process job (ADR 0024, M3): it takes a committed upload to a ready
// asset of encrypted, keyframe-aligned CMAF/fMP4 HLS renditions.
//
//	committed -> processing
//	  stream the source into the job's private work directory, hashing it in the same pass
//	  probe + validate, pick the ladder          (a bad file fails the asset for good)
//	  create-or-get the asset's content key      (once, before any rendition work)
//	  ONE FFmpeg process: decode once, split, encode every rung, write fMP4 HLS segments
//	  for each rendition: encrypt each segment (AES-128-CBC, own IV), upload, hash what is stored
//	  write and upload the canonical playlists
//	  register every object in asset_artifacts and move processing -> ready, in one transaction
//
// The content key and the plaintext segments never touch storage, a log line, a job argument or an
// error. Plaintext exists only in the job's work directory, mode 0700, which is deleted when the
// job ends, and in memory for the length of one segment.
//
// The job is idempotent: a retry starts by removing the previous attempt's delivery objects and
// artifact rows, reuses the content key, and runs every step again.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

// Failure codes recorded on an asset that cannot be processed (assets.failure_code). They are
// stable, lower_snake_case and carry no detail.
const (
	// FailureInvalidMedia: the file is not a supported, valid video or exceeds a limit.
	FailureInvalidMedia = "invalid_media"
	// FailureTranscode: FFmpeg could not transcode a file that passed validation.
	FailureTranscode = "transcode_failed"
	// FailureTranscodeTimeout: the transcode ran past CIPHERFRAME_TRANSCODE_TIMEOUT.
	FailureTranscodeTimeout = "transcode_timeout"
	// FailureSourceMismatch: the stored source is not the size the upload declared.
	FailureSourceMismatch = "source_mismatch"
	// FailureProcessing: a transient failure (storage, database, ...) outlasted every retry.
	FailureProcessing = "processing_failed"
)

// jobOverhead is added to the transcode timeout to get the job's own limit: it covers the download,
// the upload and the database work around the transcode.
const jobOverhead = time.Hour

// Deps are the collaborators of the Processor.
type Deps struct {
	Repo     Repo
	Source   storage.Store // the source bucket
	Delivery storage.Store // the delivery bucket
	Keys     KeyEnsurer
	Tools    Toolchain
	Limits   media.Limits
	// WorkDir is the base directory for per-job directories (CIPHERFRAME_WORK_DIR).
	WorkDir string
	// TranscodeTimeout bounds the FFmpeg run (CIPHERFRAME_TRANSCODE_TIMEOUT).
	TranscodeTimeout time.Duration
	Log              *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
	// ProgressInterval is how often the progress column is written; default 3 seconds.
	ProgressInterval time.Duration
}

// Processor runs asset.process jobs.
type Processor struct {
	Deps
}

// NewProcessor validates deps and returns a Processor. It creates the work directory (mode 0700).
func NewProcessor(d Deps) (*Processor, error) {
	switch {
	case d.Repo == nil || d.Source == nil || d.Delivery == nil || d.Keys == nil || d.Tools == nil:
		return nil, errors.New("pipeline: repository, both stores, key source and tools are required")
	case d.TranscodeTimeout <= 0:
		return nil, errors.New("pipeline: transcode timeout must be positive")
	case d.WorkDir == "":
		return nil, errors.New("pipeline: work directory is required")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.ProgressInterval <= 0 {
		d.ProgressInterval = 3 * time.Second
	}
	if err := prepareWorkDir(d.WorkDir); err != nil {
		return nil, err
	}
	if n, err := sweepStaleJobDirs(d.WorkDir, d.TranscodeTimeout+staleJobGrace, d.Now()); err != nil {
		d.Log.Warn("could not sweep stale job directories", slog.String("error", err.Error()))
	} else if n > 0 {
		d.Log.Info("removed stale job directories", slog.Int("count", n))
	}
	return &Processor{Deps: d}, nil
}

// staleJobGrace is added to the transcode timeout before a leftover job directory counts as stale.
const staleJobGrace = time.Hour

// sweepStaleJobDirs removes job directories (job-*) last modified before now-olderThan. A worker
// killed without cleanup (SIGKILL, OOM) can leave plaintext segments behind; a directory older than
// any job may run cannot belong to a live job, even if several workers share the base directory.
func sweepStaleJobDirs(dir string, olderThan time.Duration, now time.Time) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("pipeline: read work directory: %w", err)
	}
	removed := 0
	var errs []error
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "job-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) < olderThan {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

// prepareWorkDir creates the base directory with mode 0700 and refuses one that other users can
// reach: it holds plaintext segments while jobs run.
func prepareWorkDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("pipeline: create work directory: %w", err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("pipeline: work directory: %w", err)
	}
	if !st.IsDir() {
		return errors.New("pipeline: work directory is not a directory")
	}
	if st.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // 0700 is the strictest useful mode for a directory
			return errors.New("pipeline: work directory is accessible to other users and cannot be restricted")
		}
	}
	return nil
}

// Register registers the asset.process job kind. The kind is only registered in the worker role.
func Register(reg *jobs.Registry, d Deps) error {
	p, err := NewProcessor(d)
	if err != nil {
		return err
	}
	return jobs.Register(reg, p.Handle, jobs.KindConfig{Timeout: d.TranscodeTimeout + jobOverhead})
}

// permanentError marks a failure that no retry can fix. The asset is failed with code.
type permanentError struct {
	code string
	err  error
}

func (e *permanentError) Error() string { return "pipeline: " + e.code + ": " + e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func permanent(code string, err error) error { return &permanentError{code: code, err: err} }

// errsCode maps a failure code to the registered error code a cancelled job shows in the
// dead-letter list.
func (e *permanentError) errsCode() errs.Code {
	switch e.code {
	case FailureInvalidMedia:
		return errs.InvalidRequest
	case FailureTranscodeTimeout:
		return errs.Timeout
	case FailureSourceMismatch:
		return errs.Conflict
	}
	return errs.InternalError
}

// Handle works one asset.process job.
func (p *Processor) Handle(ctx context.Context, job jobs.Job[uploads.ProcessArgs]) error {
	tenant, assetID := job.Args.TenantID, job.Args.AssetID
	if tenant.IsZero() || assetID.IsZero() {
		return jobs.Cancel(errs.New(errs.InvalidRequest, "the job has no asset"))
	}
	log := p.Log.With(slog.String("job", "asset.process"), slog.String("tenant_id", tenant.String()),
		slog.String("asset_id", assetID.String()), slog.Int("attempt", job.Attempt))

	asset, err := p.Repo.GetAsset(ctx, tenant, assetID)
	if err != nil {
		if isCode(err, errs.NotFound) {
			return jobs.Cancel(err)
		}
		return err
	}
	asset, proceed, err := p.claim(ctx, asset, log)
	if err != nil || !proceed {
		return err
	}

	start := p.Now()
	err = p.process(ctx, asset, log)
	if err == nil {
		log.InfoContext(ctx, "asset processed", slog.Duration("elapsed", p.Now().Sub(start)))
		return nil
	}
	return p.handleFailure(ctx, job, asset, err, log)
}

// claim moves a committed asset to processing with a compare-and-set. A retried job finds the asset
// already processing and carries on; an asset in any other state needs no work.
func (p *Processor) claim(ctx context.Context, asset db.Asset, log *slog.Logger) (db.Asset, bool, error) {
	switch asset.State {
	case db.AssetProcessing:
		return asset, true, nil
	case db.AssetReady, db.AssetFailed, db.AssetDeleted:
		log.InfoContext(ctx, "nothing to do: the asset is already finished", slog.String("state", string(asset.State)))
		return asset, false, nil
	case db.AssetCommitted:
	default:
		return asset, false, jobs.Cancel(errs.New(errs.Conflict, "the asset has not been committed"))
	}
	moved, err := p.Repo.TransitionAsset(ctx, asset.TenantID, asset.ID, db.Transition{
		From: db.AssetCommitted, To: db.AssetProcessing, At: p.Now().UTC(),
	})
	if err == nil {
		return moved, true, nil
	}
	if !errors.Is(err, db.ErrStateChanged) {
		return asset, false, err
	}
	// Lost the compare-and-set: look at where the asset is now.
	cur, gerr := p.Repo.GetAsset(ctx, asset.TenantID, asset.ID)
	if gerr != nil {
		return asset, false, gerr
	}
	if cur.State == db.AssetProcessing {
		return cur, true, nil
	}
	log.InfoContext(ctx, "nothing to do: the asset changed state", slog.String("state", string(cur.State)))
	return cur, false, nil
}

// handleFailure decides what a failed run means for the asset and for the job.
func (p *Processor) handleFailure(ctx context.Context, job jobs.Job[uploads.ProcessArgs], asset db.Asset, err error, log *slog.Logger) error {
	var perm *permanentError
	switch {
	case errors.As(err, &perm):
		log.WarnContext(ctx, "asset failed", slog.String("failure_code", perm.code), slog.String("error", err.Error()))
		if ferr := p.failAsset(ctx, asset, perm.code, log); ferr != nil {
			// The failure could not be recorded; retry so the asset does not stay processing.
			return ferr
		}
		return jobs.Cancel(errs.New(perm.errsCode(), "processing failed"))
	case ctx.Err() != nil:
		// Shutdown or the job's own deadline: leave the asset processing; the next attempt
		// starts clean.
		log.WarnContext(ctx, "processing interrupted", slog.String("error", err.Error()))
		return err
	case job.Attempt >= job.MaxAttempts:
		log.ErrorContext(ctx, "processing failed on the last attempt", slog.String("error", err.Error()))
		if ferr := p.failAsset(ctx, asset, FailureProcessing, log); ferr != nil {
			return ferr
		}
		return err
	}
	log.WarnContext(ctx, "processing failed, will retry", slog.String("error", err.Error()))
	return err
}

// failAsset removes what the attempts left in the delivery bucket and moves the asset to failed.
// It runs on its own context: the job's may be the thing that ended.
func (p *Processor) failAsset(ctx context.Context, asset db.Asset, code string, log *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	if err := p.cleanDelivery(ctx, asset); err != nil {
		log.WarnContext(ctx, "could not remove partial output", slog.String("error", err.Error()))
	}
	_, err := p.Repo.TransitionAsset(ctx, asset.TenantID, asset.ID, db.Transition{
		From: db.AssetProcessing, To: db.AssetFailed, FailureCode: code, At: p.Now().UTC(),
	})
	if err != nil && !errors.Is(err, db.ErrStateChanged) {
		log.ErrorContext(ctx, "could not record the failure", slog.String("error", err.Error()))
		return err
	}
	return nil
}
