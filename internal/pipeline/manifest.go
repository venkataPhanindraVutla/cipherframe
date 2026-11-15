package pipeline

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/media"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
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
	in, err := manifestInput(asset, src, ladder, info, pub, ffmpeg, cmp.Or(p.X264Preset, media.X264Preset), at)
	if err != nil {
		return nil, err
	}
	built, err := manifest.Build(in)
	if err != nil {
		return nil, fmt.Errorf("pipeline: build the manifest: %w", err)
	}
	return p.signManifest(ctx, asset, built, at)
}

// signManifest signs the canonical manifest as a DSSE envelope and returns the row to store.
func (p *Processor) signManifest(ctx context.Context, asset db.Asset, built *manifest.Built, at time.Time) (*db.AssetManifest, error) {
	return SignManifest(ctx, p.Signer, asset.TenantID, asset.ID, built, at)
}

// SignManifest signs a built manifest as a DSSE envelope with the current key and returns the row
// to store. The subtitle service uses it too, to re-sign after a track changes (ADR 0044).
func SignManifest(ctx context.Context, signer signing.Signer, tenant id.TenantID, asset id.AssetID, built *manifest.Built, at time.Time) (*db.AssetManifest, error) {
	keyID, sig, err := signer.Sign(ctx, dsse.PAE(manifest.PayloadType, built.Canonical))
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
		AssetID: asset, TenantID: tenant, KeyID: keyID,
		PayloadSHA256: payloadSum[:], TopRoot: built.TopRoot[:], Envelope: encoded, CreatedAt: at,
	}, nil
}

// DecodeManifest reads the manifest a stored envelope carries (the signature is not checked: the
// row is the service's own).
func DecodeManifest(envelope []byte) (manifest.Manifest, error) {
	var m manifest.Manifest
	env, err := dsse.Decode(envelope)
	if err != nil {
		return m, fmt.Errorf("pipeline: read the stored manifest: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, errors.New("pipeline: the stored manifest does not decode")
	}
	return m, nil
}

// sealMasked adds the masked variant to the asset's stored manifest and signs it again. The stored
// manifest's own members are carried over as signed; only the masked section is new.
func (p *Processor) sealMasked(ctx context.Context, asset db.Asset, current db.AssetManifest, ladder []media.Rendition, pub published, faces, frames int, at time.Time) (*db.AssetManifest, error) {
	m, err := DecodeManifest(current.Envelope)
	if err != nil {
		return nil, err
	}
	prefix := keys.VariantHLSPrefix(asset.TenantID, asset.ID, keys.Masked)
	renditions, master, err := renditionInputs(prefix, pub)
	if err != nil {
		return nil, err
	}
	thumbs, err := thumbnailInputs(prefix, pub)
	if err != nil {
		return nil, err
	}
	built, err := manifest.WithMasked(m, manifest.MaskedInput{
		CreatedAt: at, FacesDetected: faces, Frames: frames, Rungs: rungsOf(ladder), Renditions: renditions, Master: master,
		Thumbnails: thumbs,
	})
	if err != nil {
		return nil, fmt.Errorf("pipeline: build the manifest: %w", err)
	}
	return p.signManifest(ctx, asset, built, at)
}

// manifestInput gathers what manifest.Build needs from what the pipeline already has: the
// registry rows in publish order and the rendition summaries.
func manifestInput(asset db.Asset, src sourceDigest, ladder []media.Rendition, info media.Info, pub published, ffmpeg, preset string, at time.Time) (manifest.Input, error) {
	in := manifest.Input{
		AssetID: asset.ID.String(), TenantID: asset.TenantID.String(), CreatedAt: at,
		PipelineVersion: version.Get().Version, SourceSHA256: src.sha256, SourceSize: src.size,
	}
	var err error
	prefix := keys.HLSPrefix(asset.TenantID, asset.ID)
	if in.Renditions, in.Master, err = renditionInputs(prefix, pub); err != nil {
		return in, err
	}
	if in.Thumbnails, err = thumbnailInputs(prefix, pub); err != nil {
		return in, err
	}

	enc := manifest.Encoder{
		FFmpeg: ffmpeg, VideoCodec: "libx264", Preset: preset,
		FrameRate: rational(media.OutputFrameRate(info.Video.FrameRate).Expr), SegmentSeconds: media.SegmentSeconds,
		KeyframeSeconds: media.KeyframeSeconds, Encryption: "AES-128",
	}
	enc.Rungs = rungsOf(ladder)
	in.Encoder = enc
	return in, nil
}

// rungsOf records the encoder settings of each rendition.
func rungsOf(ladder []media.Rendition) []manifest.Rung {
	rungs := make([]manifest.Rung, 0, len(ladder))
	for _, r := range ladder {
		rungs = append(rungs, manifest.Rung{
			Name: r.Name, CRF: r.CRF, MaxrateKbps: r.MaxrateKbps, BufsizeKbps: r.BufsizeKbps, AudioKbps: r.AudioKbps,
		})
	}
	return rungs
}

// renditionInputs turns the registry rows of one variant, in publish order, into the manifest's
// per-rendition input and its master playlist. Paths are made relative to prefix, the variant's
// HLS prefix.
func renditionInputs(prefix string, pub published) ([]manifest.RenditionInput, manifest.StoredObject, error) {
	var master manifest.StoredObject
	stored := func(a db.Artifact) (manifest.StoredObject, error) {
		if len(a.SHA256) != sha256.Size || !strings.HasPrefix(a.ObjectKey, prefix) {
			return manifest.StoredObject{}, errors.New("pipeline: an artifact does not belong to the variant's HLS prefix")
		}
		o := manifest.StoredObject{Path: strings.TrimPrefix(a.ObjectKey, prefix), Size: a.SizeBytes}
		copy(o.SHA256[:], a.SHA256)
		return o, nil
	}

	byRendition := make(map[string]*manifest.RenditionInput, len(pub.summary))
	renditions := make([]manifest.RenditionInput, len(pub.summary))
	for i, s := range pub.summary {
		renditions[i] = manifest.RenditionInput{Name: s.Name, Width: s.Width, Height: s.Height, Bandwidth: s.Bandwidth}
		byRendition[s.Name] = &renditions[i]
	}
	for _, a := range pub.artifacts {
		o, err := stored(a)
		if err != nil {
			return nil, master, err
		}
		if a.Kind == db.ArtifactMaster {
			master = o
			continue
		}
		if thumbnailKinds[a.Kind] != "" { // listed by thumbnailInputs
			continue
		}
		r := byRendition[a.Rendition]
		if r == nil {
			return nil, master, errors.New("pipeline: an artifact names an unknown rendition")
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
	return renditions, master, nil
}

// thumbnailKinds maps the registry kinds of a variant's thumbnails to the manifest's.
var thumbnailKinds = map[db.ArtifactKind]string{
	db.ArtifactPoster: manifest.KindPoster, db.ArtifactSprite: manifest.KindSprite, db.ArtifactThumbnails: manifest.KindThumbnails,
}

// thumbnailInputs turns the thumbnail rows of one variant into the manifest's input, paths relative
// to prefix, the variant's HLS prefix. A variant without any gives nil.
func thumbnailInputs(prefix string, pub published) ([]manifest.Thumbnail, error) {
	var out []manifest.Thumbnail
	for _, a := range pub.artifacts {
		kind := thumbnailKinds[a.Kind]
		if kind == "" {
			continue
		}
		if len(a.SHA256) != sha256.Size || !strings.HasPrefix(a.ObjectKey, prefix) {
			return nil, errors.New("pipeline: a thumbnail does not belong to the variant's HLS prefix")
		}
		o := manifest.StoredObject{Path: strings.TrimPrefix(a.ObjectKey, prefix), Size: a.SizeBytes}
		copy(o.SHA256[:], a.SHA256)
		out = append(out, manifest.Thumbnail{Kind: kind, Object: o})
	}
	return out, nil
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
