package pipeline

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/version"
)

// versionTimeout bounds the one-off `ffmpeg -version` run.
const versionTimeout = 30 * time.Second

// sourceDigest is the hash and size of the source as measured while it was downloaded.
type sourceDigest struct {
	sha256 [sha256.Size]byte
	size   int64
}

// ffmpegVersionString returns the FFmpeg version line, reading it once and caching the first
// success. A failure is not cached.
func (p *Processor) ffmpegVersionString(ctx context.Context) (string, error) {
	p.versionMu.Lock()
	defer p.versionMu.Unlock()
	if p.ffmpegVersion != "" {
		return p.ffmpegVersion, nil
	}
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	v, err := p.Tools.Version(ctx)
	if err != nil {
		return "", fmt.Errorf("pipeline: read the ffmpeg version: %w", err)
	}
	p.ffmpegVersion = v
	return v, nil
}

// sealManifest builds the integrity manifest of a published asset, signs it as a DSSE envelope and
// returns the row to store with the completion. A signer failure is returned as an ordinary error,
// which the job retries. Neither the payload nor the signature is ever logged.
func (p *Processor) sealManifest(ctx context.Context, asset db.Asset, src sourceDigest, ladder []media.Rendition, info media.Info, pub published, at time.Time) (*db.AssetManifest, error) {
	ffmpeg, err := p.ffmpegVersionString(ctx)
	if err != nil {
		return nil, err
	}
	in, err := manifestInput(asset, src, ladder, info, pub, ffmpeg, at)
	if err != nil {
		return nil, err
	}
	built, err := manifest.Build(in)
	if err != nil {
		return nil, fmt.Errorf("pipeline: build the manifest: %w", err)
	}
	keyID, sig, err := p.Signer.Sign(ctx, dsse.PAE(manifest.PayloadType, built.Canonical))
	if err != nil {
		return nil, fmt.Errorf("pipeline: sign the manifest: %w", err)
	}
	if keyID == "" || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("pipeline: the signer returned an unusable signature")
	}
	env := dsse.Envelope{
		PayloadType: manifest.PayloadType,
		Payload:     built.Canonical,
		Signatures:  []dsse.Signature{{KeyID: keyID, Sig: sig}},
	}
	encoded, err := env.Encode()
	if err != nil {
		return nil, fmt.Errorf("pipeline: encode the envelope: %w", err)
	}
	payloadSum := sha256.Sum256(built.Canonical)
	return &db.AssetManifest{
		AssetID: asset.ID, TenantID: asset.TenantID, KeyID: keyID,
		PayloadSHA256: payloadSum[:], TopRoot: built.TopRoot[:], Envelope: encoded, CreatedAt: at,
	}, nil
}

// manifestInput gathers what manifest.Build needs from what the pipeline already has: the
// registry rows in publish order and the rendition summaries.
func manifestInput(asset db.Asset, src sourceDigest, ladder []media.Rendition, info media.Info, pub published, ffmpeg string, at time.Time) (manifest.Input, error) {
	prefix := keys.HLSPrefix(asset.TenantID, asset.ID)
	stored := func(a db.Artifact) (manifest.StoredObject, error) {
		if len(a.SHA256) != sha256.Size || !strings.HasPrefix(a.ObjectKey, prefix) {
			return manifest.StoredObject{}, errors.New("pipeline: an artifact does not belong to the asset's HLS prefix")
		}
		o := manifest.StoredObject{Path: strings.TrimPrefix(a.ObjectKey, prefix), Size: a.SizeBytes}
		copy(o.SHA256[:], a.SHA256)
		return o, nil
	}

	byRendition := make(map[string]*manifest.RenditionInput, len(pub.summary))
	in := manifest.Input{
		AssetID: asset.ID.String(), TenantID: asset.TenantID.String(), CreatedAt: at,
		PipelineVersion: version.Get().Version, SourceSHA256: src.sha256, SourceSize: src.size,
	}
	in.Renditions = make([]manifest.RenditionInput, len(pub.summary))
	for i, s := range pub.summary {
		in.Renditions[i] = manifest.RenditionInput{Name: s.Name, Width: s.Width, Height: s.Height, Bandwidth: s.Bandwidth}
		byRendition[s.Name] = &in.Renditions[i]
	}
	for _, a := range pub.artifacts {
		o, err := stored(a)
		if err != nil {
			return in, err
		}
		if a.Kind == db.ArtifactMaster {
			in.Master = o
			continue
		}
		r := byRendition[a.Rendition]
		if r == nil {
			return in, errors.New("pipeline: an artifact names an unknown rendition")
		}
		switch a.Kind {
		case db.ArtifactInit:
			r.Init = o
		case db.ArtifactSegment:
			r.Segments = append(r.Segments, o)
		case db.ArtifactPlaylist:
			r.Playlist = o
		}
	}

	enc := manifest.Encoder{
		FFmpeg: ffmpeg, VideoCodec: "libx264", Preset: media.X264Preset,
		FrameRate: rational(media.OutputFrameRate(info.Video.FrameRate).Expr), SegmentSeconds: media.SegmentSeconds,
		KeyframeSeconds: media.KeyframeSeconds, Encryption: "AES-128",
	}
	for _, r := range ladder {
		enc.Rungs = append(enc.Rungs, manifest.Rung{
			Name: r.Name, CRF: r.CRF, MaxrateKbps: r.MaxrateKbps, BufsizeKbps: r.BufsizeKbps, AudioKbps: r.AudioKbps,
		})
	}
	in.Encoder = enc
	return in, nil
}

// rational writes an FFmpeg frame rate expression ("30", "30000/1001" or "23.976") as a rational
// string, so no decimal fraction reaches the manifest.
func rational(expr string) string {
	if strings.Contains(expr, "/") {
		return expr
	}
	whole, frac, found := strings.Cut(expr, ".")
	if !found {
		return expr + "/1"
	}
	den := "1" + strings.Repeat("0", len(frac))
	num, err := strconv.ParseInt(whole+frac, 10, 64)
	if err != nil {
		return expr + "/1"
	}
	return strconv.FormatInt(num, 10) + "/" + den
}
