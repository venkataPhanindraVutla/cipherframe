package db

import (
	"context"
	"encoding/json"
	"slices"
	"time"
	"uuid"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
)

// The extra video codecs a tenant can turn on (ADR 0064): the values of the extra_codecs setting.
const (
	CodecHEVC = "hevc"
	CodecAV1  = "av1"
)

// ExtraCodecs lists the allowed values of the extra_codecs setting, in the order they are made and listed.
var ExtraCodecs = []string{CodecHEVC, CodecAV1}

// ValidExtraCodec reports whether c is one of ExtraCodecs.
func ValidExtraCodec(c string) bool { return slices.Contains(ExtraCodecs, c) }

// Reasons an extra codec was not made (CodecFailure.Reason): fixed lower_snake_case codes that carry no
// detail, like an asset's failure_code.
const (
	// CodecEncoderUnavailable: the worker's FFmpeg has no encoder for the codec.
	CodecEncoderUnavailable = "encoder_unavailable"
	// CodecTranscodeFailed: FFmpeg failed on the codec's renditions (the H.264 ones were fine).
	CodecTranscodeFailed = "transcode_failed"
	// CodecTranscodeTimeout: the codec's transcode ran past the transcode timeout.
	CodecTranscodeTimeout = "transcode_timeout"
	// CodecOutputInvalid: FFmpeg's output for the codec was unusable (missing segments, misaligned
	// keyframes, an unreadable codec configuration).
	CodecOutputInvalid = "output_invalid"
)

// CodecFailure records an extra codec an asset asked for and did not get.
type CodecFailure struct {
	Codec  string `json:"codec"`
	Reason string `json:"reason"`
}

// parseCodecFailures reads the extra_codec_failures column. A column that does not parse is "none":
// the table's CHECK only guarantees an array.
func parseCodecFailures(raw []byte) []CodecFailure {
	var out []CodecFailure
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// UpsertWorkerCapabilities records that worker workerID, a running worker process, can encode codecs
// (a subset of ExtraCodecs) as of at. The worker calls it at startup and then on every heartbeat.
func (r *Repos) UpsertWorkerCapabilities(ctx context.Context, workerID uuid.UUID, codecs []string, at time.Time) error {
	if codecs == nil {
		codecs = []string{}
	}
	return mapError(r.q.UpsertWorkerCapabilities(ctx, dbgen.UpsertWorkerCapabilitiesParams{
		WorkerID: rawToPG(workerID), Codecs: codecs, At: at,
	}))
}

// RecentWorkerCodecs returns the extra codecs reported by a worker seen at or after cutoff.
func (r *Repos) RecentWorkerCodecs(ctx context.Context, cutoff time.Time) ([]string, error) {
	out, err := r.q.ListRecentWorkerCodecs(ctx, cutoff)
	return out, mapError(err)
}

// PruneWorkerCapabilities deletes the rows of workers last seen before cutoff and returns how many.
func (r *Repos) PruneWorkerCapabilities(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := r.q.DeleteStaleWorkerCapabilities(ctx, cutoff)
	return n, mapError(err)
}
