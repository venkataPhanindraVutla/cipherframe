package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Content types of the stored objects. Encrypted segments are not media any player could open, so
// they are plain bytes.
const (
	typeSegment  = "application/octet-stream"
	typeInit     = "video/mp4"
	typePlaylist = "application/vnd.apple.mpegurl"
)

// bandwidthMinSegment: segments shorter than this are left out of the peak bandwidth when longer
// ones exist. A final segment of a few frames has a meaningless instantaneous bitrate that would
// make players avoid the rendition.
const bandwidthMinSegment = media.SegmentSeconds * time.Second / 2

// RenditionSummary is one entry of the assets.renditions JSON.
type RenditionSummary struct {
	Name             string  `json:"name"`
	Width            int     `json:"width"`
	Height           int     `json:"height"`
	Bandwidth        int64   `json:"bandwidth"`
	AverageBandwidth int64   `json:"average_bandwidth"`
	Codecs           string  `json:"codecs"`
	FrameRate        float64 `json:"frame_rate"`
	Segments         int     `json:"segments"`
	Bytes            int64   `json:"bytes"`
}

// published is the result of encrypting and uploading every rendition.
type published struct {
	artifacts []db.Artifact
	summary   []RenditionSummary
	duration  time.Duration
}

// publish encrypts each rendition's media segments, uploads them with the init segments, then
// writes and uploads the canonical playlists. Each object's SHA-256 is computed over the bytes as
// stored, and each is returned as an artifact for the registry.
func (p *Processor) publish(ctx context.Context, asset db.Asset, key []byte, outs []media.RenditionOutput, info media.Info, log *slog.Logger) (published, error) {
	t0 := p.Now()
	rate := media.OutputFrameRate(info.Video.FrameRate)
	var pub published
	var variants []hls.Variant

	put := func(kind db.ArtifactKind, rendition, objKey, contentType string, body []byte) error {
		sum := sha256.Sum256(body)
		if err := p.Delivery.Put(ctx, objKey, bytes.NewReader(body), int64(len(body)), contentType); err != nil {
			return fmt.Errorf("pipeline: upload: %w", err)
		}
		pub.artifacts = append(pub.artifacts, db.Artifact{
			AssetID: asset.ID, Kind: kind, Rendition: rendition, Bucket: string(keys.Delivery),
			ObjectKey: objKey, SizeBytes: int64(len(body)), SHA256: sum[:],
		})
		return nil
	}

	for i, o := range outs {
		name, err := keys.ParseRendition(o.Rendition.Name)
		if err != nil {
			return pub, err
		}
		rname := name.String()

		// The init segment holds codec configuration only and is stored as FFmpeg wrote it (see
		// docs/encryption.md). Its codec strings go into the master playlist.
		initBytes, err := os.ReadFile(o.InitPath)
		if err != nil {
			return pub, fmt.Errorf("pipeline: read init segment: %w", err)
		}
		codecs, err := codecString(initBytes, info.Audio != nil)
		if err != nil {
			return pub, err
		}
		initKey := keys.InitSegment(asset.TenantID, asset.ID, name)
		if err := put(db.ArtifactInit, rname, initKey, typeInit, initBytes); err != nil {
			return pub, err
		}

		pl := hls.MediaPlaylist{InitURI: path.Base(initKey)}
		var total, peakNum int64
		var peakDur, totalDur time.Duration
		var peakAny int64
		var peakAnyDur time.Duration
		for _, s := range o.Segments {
			segKey := keys.Segment(asset.TenantID, asset.ID, name, s.Index)
			iv, size, sum, err := p.encryptAndUpload(ctx, key, s.Path, segKey)
			if err != nil {
				return pub, err
			}
			pub.artifacts = append(pub.artifacts, db.Artifact{
				AssetID: asset.ID, Kind: db.ArtifactSegment, Rendition: rname, Bucket: string(keys.Delivery),
				ObjectKey: segKey, SizeBytes: size, SHA256: sum[:],
			})
			pl.Segments = append(pl.Segments, hls.Segment{URI: path.Base(segKey), Duration: s.Duration, IV: iv})
			total += size
			totalDur += s.Duration
			// Peak bitrate: bytes * 8 / seconds, kept as a fraction to compare without division.
			if s.Duration >= bandwidthMinSegment && (peakDur == 0 || size*peakDur.Nanoseconds() > peakNum*s.Duration.Nanoseconds()) {
				peakNum, peakDur = size, s.Duration
			}
			if peakAnyDur == 0 || size*peakAnyDur.Nanoseconds() > peakAny*s.Duration.Nanoseconds() {
				peakAny, peakAnyDur = size, s.Duration
			}
		}
		if peakDur == 0 { // no segment of at least half the target: take the peak of whatever exists
			peakNum, peakDur = peakAny, peakAnyDur
		}
		average := bitrate(total, totalDur)
		// BANDWIDTH is a peak, so it is never below the average (RFC 8216 4.3.4.2): a short final
		// segment that was left out of the peak can still pull the average above it.
		bandwidth := max(bitrate(peakNum, peakDur), average)

		text, err := hls.RenderMedia(pl)
		if err != nil {
			return pub, err
		}
		plKey := keys.Playlist(asset.TenantID, asset.ID, name)
		if err := put(db.ArtifactPlaylist, rname, plKey, typePlaylist, []byte(text)); err != nil {
			return pub, err
		}

		variants = append(variants, hls.Variant{
			URI:       strings.TrimPrefix(plKey, keys.HLSPrefix(asset.TenantID, asset.ID)),
			Bandwidth: bandwidth, AverageBandwidth: average,
			Width: o.Rendition.Width, Height: o.Rendition.Height, Codecs: codecs, FrameRate: rate.FPS,
		})
		pub.summary = append(pub.summary, RenditionSummary{
			Name: rname, Width: o.Rendition.Width, Height: o.Rendition.Height, Bandwidth: bandwidth,
			AverageBandwidth: average, Codecs: codecs, FrameRate: rate.FPS, Segments: len(o.Segments), Bytes: total,
		})
		if i == 0 {
			pub.duration = totalDur
		}
		// The upload fills the share of progress between the transcode and "ready".
		_ = p.Repo.SetProgress(ctx, asset.TenantID, asset.ID, transcodeShare+(uploadShare-transcodeShare)*(i+1)/len(outs))
	}

	master, err := hls.RenderMaster(variants)
	if err != nil {
		return pub, err
	}
	if err := put(db.ArtifactMaster, "", keys.Master(asset.TenantID, asset.ID), typePlaylist, []byte(master)); err != nil {
		return pub, err
	}
	log.InfoContext(ctx, "output published", slog.Int("objects", len(pub.artifacts)), slog.Duration("elapsed", p.Now().Sub(t0)))
	return pub, nil
}

// encryptAndUpload reads one plaintext segment, encrypts it in memory with a fresh IV, uploads the
// ciphertext and returns the IV, the stored size and the SHA-256 of the stored bytes. The plaintext
// file is deleted as soon as it has been read and the plaintext buffer is cleared before the upload
// starts, so at most one segment of plaintext (and its ciphertext) is in memory at a time.
func (p *Processor) encryptAndUpload(ctx context.Context, key []byte, file, objectKey string) (hls.IV, int64, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	plain, err := os.ReadFile(file) //nolint:gosec // a file FFmpeg wrote in the job's private directory
	if err != nil {
		return hls.IV{}, 0, zero, fmt.Errorf("pipeline: read segment: %w", err)
	}
	_ = os.Remove(file)
	iv, err := hls.NewIV()
	if err != nil {
		clear(plain)
		return hls.IV{}, 0, zero, err
	}
	ct, err := hls.EncryptSegment(key, iv, plain)
	clear(plain)
	if err != nil {
		return hls.IV{}, 0, zero, err
	}
	sum := sha256.Sum256(ct)
	if err := p.Delivery.Put(ctx, objectKey, bytes.NewReader(ct), int64(len(ct)), typeSegment); err != nil {
		return hls.IV{}, 0, zero, fmt.Errorf("pipeline: upload: %w", err)
	}
	return iv, int64(len(ct)), sum, nil
}

// codecString builds the CODECS attribute from the init segment: the video track's string and, when
// the source has audio, the audio track's.
func codecString(initSeg []byte, audio bool) (string, error) {
	v, err := hls.VideoCodec(initSeg)
	if err != nil {
		return "", err
	}
	if !audio {
		return v, nil
	}
	a, err := hls.AudioCodec(initSeg)
	if err != nil {
		return "", err
	}
	return v + "," + a, nil
}

// bitrate is bits per second for size bytes over d, at least 1.
func bitrate(size int64, d time.Duration) int64 {
	if d <= 0 {
		return 1
	}
	return max(int64(float64(size)*8/d.Seconds()), 1)
}
