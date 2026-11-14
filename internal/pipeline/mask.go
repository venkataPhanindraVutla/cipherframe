package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"time"
	"uuid"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// MaskKind is the River job kind that builds the masked variant of an asset (ADR 0036). Do not
// rename it once jobs of that kind exist.
const MaskKind = "asset.mask"

// MaskTaskKind is the kind of the hand-off task the masker claims (spec/jobs/kinds).
const MaskTaskKind = "media.mask_faces"

// Failure codes of the masked variant. They are only logged: the asset itself stays ready.
const (
	// FailureMasking: the masker reported a final failure, or its result did not follow the contract.
	FailureMasking = "masking_failed"
	// FailureMaskTimeout: the masker did not finish within CIPHERFRAME_WORKER_MASK_TIMEOUT.
	FailureMaskTimeout = "masking_timeout"
)

// MaskArgs are the arguments of the asset.mask job: identifiers only.
type MaskArgs struct {
	TenantID id.TenantID `json:"tenant_id"`
	AssetID  id.AssetID  `json:"asset_id"`
}

// Kind implements jobs.Args.
func (MaskArgs) Kind() string { return MaskKind }

// Names inside the job directory that the masker task refers to.
const (
	maskInputName  = "source"
	maskOutputName = "masked.mp4"
)

// maskPayload is the payload of a media.mask_faces task: paths relative to the work directory.
type maskPayload struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

// maskOutput is the output of a succeeded media.mask_faces task.
type maskOutput struct {
	FacesDetected *int `json:"faces_detected"`
	Frames        *int `json:"frames"`
}

// maskTaskAttempts is how often the masker may try one task (a retryable failure or an expired
// lease). Masking is slow, so this is lower than the default.
const maskTaskAttempts = 2

// HandleMask works one asset.mask job. Everything runs in this one job, on this worker, so the
// plaintext source and the masked file only ever exist on this worker's disk (ADR 0027).
func (p *Processor) HandleMask(ctx context.Context, job jobs.Job[MaskArgs]) error {
	tenant, assetID := job.Args.TenantID, job.Args.AssetID
	if tenant.IsZero() || assetID.IsZero() {
		return jobs.Cancel(errs.New(errs.InvalidRequest, "the job has no asset"))
	}
	log := p.Log.With(slog.String("job", MaskKind), slog.String("tenant_id", tenant.String()),
		slog.String("asset_id", assetID.String()), slog.Int("attempt", job.Attempt))

	asset, err := p.Repo.GetAsset(ctx, tenant, assetID)
	if err != nil {
		if isCode(err, errs.NotFound) {
			return jobs.Cancel(err)
		}
		return err
	}
	switch {
	case !asset.MaskFaces:
		return jobs.Cancel(errs.New(errs.Conflict, "the asset was not created with mask_faces"))
	case asset.State != db.AssetReady:
		log.InfoContext(ctx, "nothing to do: the asset is not ready", slog.String("state", string(asset.State)))
		return nil
	case asset.MaskingState == db.MaskingReady:
		log.InfoContext(ctx, "nothing to do: the masked variant is already published")
		return nil
	}

	start := p.Now()
	err = p.mask(ctx, asset, log)
	if err == nil {
		log.InfoContext(ctx, "masked variant published", slog.Duration("elapsed", p.Now().Sub(start)))
		return nil
	}
	return p.handleMaskFailure(ctx, job, asset, err, log)
}

// mask runs every step for an asset whose original variant is ready.
func (p *Processor) mask(ctx context.Context, asset db.Asset, log *slog.Logger) error {
	// A retry starts clean: whatever an earlier attempt uploaded or registered for the masked
	// variant is removed first. The original variant and the manifest are not touched.
	if err := p.cleanVariant(ctx, asset, keys.Masked); err != nil {
		return fmt.Errorf("pipeline: remove the previous attempt's masked output: %w", err)
	}

	// The job's private directory, shared with the masker through the work directory. The name
	// starts with "job-", so the startup sweep covers it too.
	dir, err := os.MkdirTemp(p.WorkDir, "job-mask-")
	if err != nil {
		return fmt.Errorf("pipeline: create the job directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// 1. The source, hashed in the same pass. The source object is still there: nothing deletes
	// it when asset.process completes, and the hash must be the one recorded at that time.
	if asset.SourceKey == "" {
		return permanent(FailureSourceMissing, errors.New("the asset has no source object"))
	}
	srcPath := filepath.Join(dir, maskInputName)
	src, storedSize, err := fetchSource(ctx, p.Source, asset.SourceKey, srcPath)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return permanent(FailureSourceMissing, err)
	case err != nil:
		return err
	case storedSize != asset.SizeBytes || src.Size != asset.SourceSizeBytes || !bytes.Equal(src.SHA256[:], asset.SourceSHA256):
		return permanent(FailureSourceMismatch, errors.New("the stored source is not the one that was processed"))
	}

	// 2. Hand the file to the masker and wait.
	out, err := p.runMasker(ctx, asset, filepath.Base(dir), log)
	if err != nil {
		return err
	}

	// 3. The masked file goes through the same ladder, segmenter and encryptor as the original.
	maskedPath := filepath.Join(dir, maskOutputName)
	info, err := p.Tools.Probe(ctx, maskedPath)
	if err != nil {
		return classifyMedia(err)
	}
	renditions := media.Ladder(info)
	if len(renditions) == 0 {
		return permanent(FailureInvalidMedia, errors.New("no renditions can be made from the masked file"))
	}
	ck, err := p.Keys.Ensure(ctx, asset.TenantID, asset.ID, keys.Masked)
	if err != nil {
		return err
	}
	defer ck.Zero()
	key := ck.Bytes()
	defer clear(key)

	outDir := filepath.Join(dir, "out")
	if err := os.Mkdir(outDir, 0o700); err != nil {
		return fmt.Errorf("pipeline: create the output directory: %w", err)
	}
	spec := media.TranscodeSpec{Source: maskedPath, OutDir: outDir, Info: info, Renditions: renditions}
	if err := p.transcode(ctx, asset, spec, log); err != nil {
		return err
	}
	_ = os.Remove(maskedPath) // plaintext no longer needed on disk
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
	pub, err := p.publish(ctx, asset, keys.Masked, key, outs, info, log)
	if err != nil {
		return err
	}

	// 4. Re-sign the manifest with the masked variant added, then register everything and mark the
	// variant ready, atomically.
	current, err := p.Repo.GetManifest(ctx, asset.ID)
	if err != nil {
		return err
	}
	at := p.Now().UTC()
	sealed, err := p.sealMasked(ctx, asset, current, renditions, pub, *out.FacesDetected, *out.Frames, at)
	if err != nil {
		return err
	}
	err = p.Repo.CompleteMasking(ctx, asset.TenantID, asset.ID, pub.artifacts, *sealed, *out.FacesDetected, at)
	if errors.Is(err, db.ErrStateChanged) {
		// The asset left ready while we worked (deleted, say): do not leave the output behind.
		log.WarnContext(ctx, "the asset changed state during masking; removing the masked output")
		return p.cleanVariant(context.WithoutCancel(ctx), asset, keys.Masked)
	}
	return err
}

// runMasker creates the hand-off task for the files in the job directory and waits for its
// outcome. The await job (jobs.RegisterExternal) requeues retryable failures and expires leases;
// this only reads the row and decides when to stop waiting.
func (p *Processor) runMasker(ctx context.Context, asset db.Asset, jobDir string, log *slog.Logger) (maskOutput, error) {
	payload, err := json.Marshal(maskPayload{Input: path.Join(jobDir, maskInputName), Output: path.Join(jobDir, maskOutputName)})
	if err != nil {
		return maskOutput{}, err
	}
	aid := asset.ID
	task, err := p.Tasks.Create(ctx, jobs.Envelope{
		Kind: MaskTaskKind, TenantID: asset.TenantID, AssetID: &aid, Payload: payload,
	}, &jobs.TaskOpts{MaxAttempts: maskTaskAttempts})
	if err != nil {
		return maskOutput{}, err
	}
	log.InfoContext(ctx, "masking task created", slog.String("task_id", task.ID.String()))

	wctx, cancel := context.WithTimeout(ctx, p.MaskTimeout)
	defer cancel()
	tick := time.NewTicker(p.MaskPoll)
	defer tick.Stop()
	for {
		out, done, err := p.checkTask(wctx, task.ID, log)
		if err != nil || done {
			return out, err
		}
		select {
		case <-wctx.Done():
			if ctx.Err() != nil {
				return maskOutput{}, ctx.Err()
			}
			return maskOutput{}, permanent(FailureMaskTimeout, errors.New("the masker did not finish in time"))
		case <-tick.C:
		}
	}
}

// checkTask reads the task once. done is false while the masker still has work to do or the await
// job is about to give it another attempt.
func (p *Processor) checkTask(ctx context.Context, taskID uuid.UUID, log *slog.Logger) (maskOutput, bool, error) {
	task, err := p.Tasks.Get(ctx, taskID)
	if err != nil {
		if ctx.Err() != nil {
			return maskOutput{}, false, nil // the caller sees the deadline
		}
		return maskOutput{}, false, err
	}
	switch task.State {
	case jobs.StatePending, jobs.StateLeased:
		return maskOutput{}, false, nil
	case jobs.StateSucceeded:
		res, err := jobs.ParseResult(task.Result)
		if err != nil || res.Status != jobs.StatusSucceeded || res.TaskID != task.ID {
			return maskOutput{}, true, permanent(FailureMasking, errors.New("the masker's result does not follow the contract"))
		}
		var out maskOutput
		dec := json.NewDecoder(bytes.NewReader(res.Output))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&out); err != nil || out.FacesDetected == nil || out.Frames == nil || *out.FacesDetected < 0 || *out.Frames < 0 {
			return maskOutput{}, true, permanent(FailureMasking, errors.New("the masker's output does not follow the contract"))
		}
		return out, true, nil
	case jobs.StateFailed:
		res, err := jobs.ParseResult(task.Result)
		if err != nil || res.Status != jobs.StatusFailed || res.TaskID != task.ID {
			return maskOutput{}, true, permanent(FailureMasking, errors.New("the masker's result does not follow the contract"))
		}
		if res.Error.Retryable && task.Attempts+1 < task.MaxAttempts {
			return maskOutput{}, false, nil // the await job puts the task back to pending
		}
		log.WarnContext(ctx, "the masker failed the task", slog.String("code", res.Error.Code), slog.Bool("retryable", res.Error.Retryable))
		return maskOutput{}, true, permanent(FailureMasking, fmt.Errorf("the masker failed the task: %s", res.Error.Code))
	}
	return maskOutput{}, true, permanent(FailureMasking, errors.New("the task is in an unknown state"))
}

// handleMaskFailure decides what a failed run means for the masked variant and for the job. The
// original variant is never changed: it stays ready and playable whatever happens here.
func (p *Processor) handleMaskFailure(ctx context.Context, job jobs.Job[MaskArgs], asset db.Asset, err error, log *slog.Logger) error {
	var perm *permanentError
	switch {
	case errors.As(err, &perm):
		log.WarnContext(ctx, "masking failed", slog.String("failure_code", perm.code), slog.String("error", err.Error()))
		if ferr := p.failMasking(ctx, asset, log); ferr != nil {
			return ferr // the failure could not be recorded; retry so the state does not stay pending
		}
		return jobs.Cancel(errs.New(perm.errsCode(), "masking failed"))
	case ctx.Err() != nil:
		// Shutdown or the job's own deadline: the next attempt starts clean.
		log.WarnContext(ctx, "masking interrupted", slog.String("error", err.Error()))
		return err
	case job.Attempt >= job.MaxAttempts:
		log.ErrorContext(ctx, "masking failed on the last attempt", slog.String("error", err.Error()))
		if ferr := p.failMasking(ctx, asset, log); ferr != nil {
			return ferr
		}
		return err
	}
	log.WarnContext(ctx, "masking failed, will retry", slog.String("error", err.Error()))
	return err
}

// failMasking removes the masked variant's partial output and records masking_state failed. It runs
// on its own context: the job's may be the thing that ended.
func (p *Processor) failMasking(ctx context.Context, asset db.Asset, log *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	if err := p.cleanVariant(ctx, asset, keys.Masked); err != nil {
		log.WarnContext(ctx, "could not remove partial masked output", slog.String("error", err.Error()))
	}
	if err := p.Repo.SetMasking(ctx, asset.TenantID, asset.ID, db.MaskingFailed, nil, p.Now().UTC()); err != nil {
		log.ErrorContext(ctx, "could not record the masking failure", slog.String("error", err.Error()))
		return err
	}
	return nil
}
