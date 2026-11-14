package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
)

// mediaCheckTimeout bounds the whole FFmpeg capability check at startup.
const mediaCheckTimeout = 2 * time.Minute

// mediaTools returns the FFmpeg and FFprobe binaries the configuration selects.
func mediaTools(cfg *config.Config) media.Tools {
	return media.Tools{FFmpeg: cfg.Media.FFmpegPath, FFprobe: cfg.Media.FFprobePath}
}

// checkMediaTools verifies the configured FFmpeg and FFprobe (ADR 0024). Only the worker role runs
// them, so Run calls it for that role alone: api and edge start without FFmpeg installed. The
// error names what is missing and the settings that choose the binaries, never a path's content.
func checkMediaTools(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, mediaCheckTimeout)
	defer cancel()
	if err := mediaTools(cfg).CheckCapabilities(ctx); err != nil {
		return fmt.Errorf("worker: %w (set %s and %s, or use the cipherframe-worker image)",
			err, config.EnvFFmpegPath, config.EnvFFprobePath)
	}
	log.InfoContext(ctx, "ffmpeg capabilities verified",
		slog.String("ffmpeg", cfg.Media.FFmpegPath), slog.String("ffprobe", cfg.Media.FFprobePath))
	return nil
}

// registerProcessing registers the asset.process job (M3). The worker role is the only one that
// calls it, so api and edge never need FFmpeg or a work directory.
func registerProcessing(reg *jobs.Registry, pool *pgxpool.Pool, inserter *jobs.Queue, contentKeys *contentkey.Manager, proc *processing, log *slog.Logger) error {
	cfg := proc.Config
	repo := pipeline.NewDBRepo(pool)
	// The masker's hand-off tasks get an await job (ADR 0010): it requeues retryable failures and
	// expires leases. asset.mask itself reads the outcome, so nothing is left to do on a result.
	if err := jobs.RegisterExternal(reg, pool, jobs.ExternalConfig{
		OnResult: func(context.Context, jobs.Task, jobs.Result) error { return nil },
	}); err != nil {
		return err
	}
	return pipeline.Register(reg, pipeline.Deps{
		Repo:     repo,
		Source:   proc.Buckets.Source,
		Delivery: proc.Buckets.Delivery,
		Keys:     pipeline.ContentKeys{Pool: pool, Manager: contentKeys},
		Tools:    mediaTools(cfg),
		Signer:   proc.Signer,
		Limits: media.Limits{
			MaxDuration: cfg.Media.MaxSourceDuration, MaxWidth: cfg.Media.MaxSourceWidth, MaxHeight: cfg.Media.MaxSourceHeight,
		},
		LadderHeights:    cfg.Media.LadderHeights,
		X264Preset:       cfg.Media.X264Preset,
		WorkDir:          cfg.Media.WorkDir,
		TranscodeTimeout: cfg.Media.TranscodeTimeout,
		Tasks:            pipeline.DBTasks{Pool: pool, Queue: inserter},
		MaskTimeout:      cfg.Media.MaskTimeout,
		Log:              log,
	})
}
