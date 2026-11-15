package pipeline

import (
	"log/slog"
	"path/filepath"

	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
)

// thumbnailSpec plans the poster and sprite sheet of one variant, to be written beside the
// renditions by the same FFmpeg run (ADR 0046). It is nil when the source has no known duration.
// info and renditions are those of the file being encoded: for the masked variant, the masked file.
func thumbnailSpec(jobDir string, info media.Info, renditions []media.Rendition) *media.ThumbnailSpec {
	plan, ok := media.PlanThumbnails(info.Duration, renditions[0])
	if !ok {
		return nil
	}
	return &media.ThumbnailSpec{Dir: filepath.Join(jobDir, "thumbs"), Plan: plan}
}

// readThumbnails collects what the transcode wrote for spec. Thumbnails are an addition to the
// asset, not the asset: a run whose images are missing or not what was asked for publishes the
// variant without them (the cause is logged, never the content), where failing the asset would
// throw away a good encode.
func readThumbnails(spec media.TranscodeSpec, log *slog.Logger) *media.ThumbnailOutput {
	if spec.Thumbs == nil {
		return nil
	}
	out, err := media.ReadThumbnails(spec.Thumbs.Dir, spec.Thumbs.Plan)
	if err != nil {
		log.Warn("thumbnails skipped", slog.String("error", err.Error()))
		return nil
	}
	return &out
}
