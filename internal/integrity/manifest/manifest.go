package manifest

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/jcs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/merkle"
)

const (
	// Schema identifies this version of the format.
	Schema = "cipherframe.manifest/v1"
	// PayloadType is the DSSE payload type of a signed manifest.
	PayloadType = "application/vnd.cipherframe.manifest+json"
)

// Artifact kinds recorded in Manifest.Artifacts.
const (
	KindMaster   = "master"
	KindPlaylist = "playlist"
)

// Kinds recorded in Manifest.Thumbnails (ADR 0046).
const (
	KindPoster     = "poster"
	KindSprite     = "sprite"
	KindThumbnails = "thumbnails"
)

// Manifest is the document that is signed. Its JSON encoding is canonical (see Build); no field is
// a floating-point number.
type Manifest struct {
	Schema          string      `json:"schema"`
	AssetID         string      `json:"asset_id"`
	TenantID        string      `json:"tenant_id"`
	CreatedAt       string      `json:"created_at"`
	PipelineVersion string      `json:"pipeline_version"`
	Encoder         Encoder     `json:"encoder"`
	Renditions      []Rendition `json:"renditions"`
	Artifacts       []Artifact  `json:"artifacts"`
	TopLevel        TopLevel    `json:"top_level"`
	Source          Source      `json:"source"`
	// Masked is present once the asset's face-masked variant is published (ADR 0036).
	Masked *Masked `json:"masked,omitempty"`
	// Subtitles lists the asset's subtitle tracks, in track ID order (ADR 0044). It is absent while
	// the asset has none, so a manifest without tracks is byte for byte what it was before tracks
	// existed, and a verifier that does not know the field ignores it. The tracks are not in any
	// Merkle tree: the signature covers each track's hash, and the top-level root stays the
	// identity of the encoded media.
	Subtitles []Subtitle `json:"subtitles,omitempty"`
	// Thumbnails lists the original variant's poster, sprite sheet and thumbnail track (ADR 0046),
	// paths relative to the variant's HLS prefix. Like the subtitle list it is absent when there are
	// none, so a manifest without thumbnails is byte for byte what it was, and it is in no Merkle
	// tree: the signature covers each hash and the top-level root stays the identity of the media.
	Thumbnails []Artifact `json:"thumbnails,omitempty"`
}

// Thumbnail is one stored thumbnail object as Build and WithMasked take it. Kind is KindPoster,
// KindSprite or KindThumbnails and Object's path is relative to the variant's HLS prefix.
type Thumbnail struct {
	Kind   string
	Object StoredObject
}

// thumbnailList validates the objects and returns them as manifest artifacts in the fixed order
// poster, sprite, track. It returns nil for none; otherwise all three are required, once each.
func thumbnailList(in []Thumbnail) ([]Artifact, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]Artifact, 0, len(in))
	for _, kind := range []string{KindPoster, KindSprite, KindThumbnails} {
		for _, t := range in {
			if t.Kind != kind {
				continue
			}
			if err := checkObject("thumbnail "+kind, t.Object); err != nil {
				return nil, err
			}
			out = append(out, Artifact{Kind: kind, Path: t.Object.Path, SHA256: hex.EncodeToString(t.Object.SHA256[:]), Size: t.Object.Size})
		}
	}
	if len(in) != 3 || len(out) != 3 {
		return nil, errors.New("manifest: thumbnails are one poster, one sprite sheet and one track")
	}
	return out, nil
}

// VariantThumbnails returns the thumbnail objects the manifest records for a variant ("original" or
// "masked"), nil when it has none.
func (m Manifest) VariantThumbnails(masked bool) []Artifact {
	if !masked {
		return m.Thumbnails
	}
	if m.Masked == nil {
		return nil
	}
	return m.Masked.Thumbnails
}

// Subtitle is one subtitle track. The label a player shows is not recorded: it is a free-text title
// (the manifest holds none, ADR 0040) and not part of what must not change. Path is relative to the asset's delivery prefix, not to a
// variant's HLS prefix, because tracks are shared by the variants.
type Subtitle struct {
	ID       string `json:"id"`
	Language string `json:"language"`
	Default  bool   `json:"default"`
	Origin   string `json:"origin"` // "upload" or "import"
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// SubtitleInput is a stored track as WithSubtitles needs it.
type SubtitleInput struct {
	ID       string
	Language string
	Default  bool
	Origin   string
	Object   StoredObject // Path relative to the asset's delivery prefix
}

// WithSubtitles returns m with its subtitle list replaced by tracks (none removes it) and the new
// canonical encoding, which is what gets signed again. Every other member is carried over as it
// was signed, and TopRoot stays the original variant's top-level root.
func WithSubtitles(m Manifest, tracks []SubtitleInput) (*Built, error) {
	var top merkle.Hash
	raw, err := hex.DecodeString(m.TopLevel.Root)
	if err != nil || len(raw) != len(top) {
		return nil, errors.New("manifest: the original top-level root is malformed")
	}
	copy(top[:], raw)

	list := make([]Subtitle, 0, len(tracks))
	seen := map[string]bool{}
	defaults := 0
	for _, t := range tracks {
		if t.ID == "" || seen[t.ID] || t.Language == "" {
			return nil, errors.New("manifest: a subtitle track needs a unique ID and a language")
		}
		seen[t.ID] = true
		if err := checkObject("subtitle track", t.Object); err != nil {
			return nil, err
		}
		if t.Default {
			defaults++
		}
		list = append(list, Subtitle{
			ID: t.ID, Language: t.Language, Default: t.Default, Origin: t.Origin,
			Path: t.Object.Path, SHA256: hex.EncodeToString(t.Object.SHA256[:]), Size: t.Object.Size,
		})
	}
	if defaults > 1 {
		return nil, errors.New("manifest: at most one subtitle track is the default")
	}
	slices.SortFunc(list, func(a, b Subtitle) int { return strings.Compare(a.ID, b.ID) })
	m.Subtitles = nil
	if len(list) > 0 {
		m.Subtitles = list
	}
	canonical, err := jcs.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("manifest: encode: %w", err)
	}
	return &Built{Manifest: m, Canonical: canonical, TopRoot: top}, nil
}

// Masked describes the masked variant: the same shapes as the original's members, with every path
// relative to the masked variant's own HLS prefix. Rungs are recorded because the ladder is picked
// from the masked file, not assumed equal to the original's.
type Masked struct {
	CreatedAt     string      `json:"created_at"`
	FacesDetected int         `json:"faces_detected"`
	Frames        int         `json:"frames"`
	Rungs         []Rung      `json:"rungs"`
	Renditions    []Rendition `json:"renditions"`
	Artifacts     []Artifact  `json:"artifacts"`
	TopLevel      TopLevel    `json:"top_level"`
	// Logo is the brand logo burned into the masked variant, the same one as the original's (ADR
	// 0049); it is drawn after the faces are masked.
	Logo *Logo `json:"logo,omitempty"`
	// Thumbnails are the masked variant's own poster, sprite sheet and track, made from the masked
	// output (ADR 0046).
	Thumbnails []Artifact `json:"thumbnails,omitempty"`
}

// Encoder records how the renditions were made.
type Encoder struct {
	// FFmpeg is the first line of `ffmpeg -version`.
	FFmpeg          string `json:"ffmpeg"`
	VideoCodec      string `json:"video_codec"`
	Preset          string `json:"preset"`
	FrameRate       string `json:"frame_rate"` // a rational, "30000/1001" or "25/1"
	SegmentSeconds  int    `json:"segment_seconds"`
	KeyframeSeconds int    `json:"keyframe_seconds"`
	Encryption      string `json:"encryption"` // "AES-128"
	Rungs           []Rung `json:"rungs"`
	// Logo records the brand logo burned into the renditions (ADR 0049). It is absent for an asset
	// made without one, so a manifest without a logo is byte for byte what it was before logos.
	Logo *Logo `json:"logo,omitempty"`
}

// Logo is a brand logo as it was burned in: the SHA-256 (hex) of the stored PNG and its version ID
// identify the image, and the placement says how it was drawn. WidthPercent is the logo's share of
// the picture width, recorded because it is a constant of the encoder, not of the tenant.
type Logo struct {
	SHA256         string `json:"sha256"`
	Version        string `json:"version"`
	Corner         string `json:"corner"`
	OpacityPercent int    `json:"opacity_percent"`
	WidthPercent   int    `json:"width_percent"`
}

// Rung is the encoder setting of one rendition. The three members after AudioKbps are set only for the
// renditions of an extra codec (ADR 0064): Codec is "hevc" or "av1", VideoCodec the FFmpeg encoder that
// made it and Preset that encoder's preset when it has one. They are absent for H.264's rungs, so a
// manifest without extra codecs is byte for byte what it was before they existed.
type Rung struct {
	Name        string `json:"name"`
	CRF         int    `json:"crf"`
	MaxrateKbps int    `json:"maxrate_kbps"`
	BufsizeKbps int    `json:"bufsize_kbps"`
	AudioKbps   int    `json:"audio_kbps"`
	Codec       string `json:"codec,omitempty"`
	VideoCodec  string `json:"video_codec,omitempty"`
	Preset      string `json:"preset,omitempty"`
}

// Object is one stored object: its path, SHA-256 (hex) and size in bytes.
type Object struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Rendition is one rung of the ladder and the tree over its segments.
type Rendition struct {
	Name         string   `json:"name"`
	Width        int      `json:"width"`
	Height       int      `json:"height"`
	Bandwidth    int64    `json:"bandwidth"`
	SegmentCount int      `json:"segment_count"`
	Init         Object   `json:"init"`
	Segments     []Object `json:"segments"`
	MerkleRoot   string   `json:"merkle_root"`
}

// Artifact is a playlist. Rendition is empty for the master playlist.
type Artifact struct {
	Kind      string `json:"kind"`
	Rendition string `json:"rendition,omitempty"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}

// TopLevel is the tree that binds the renditions and the playlists together.
type TopLevel struct {
	// Order lists the leaf labels in tree order: "rendition:<name>" for each rendition root, then
	// "master", then "playlist:<name>" for each media playlist.
	Order []string `json:"order"`
	Root  string   `json:"root"`
}

// Source is the hash and size of the uploaded original, as measured at ingest. The object itself
// is never named.
type Source struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// StoredObject is an object as the pipeline stored it. Path is relative to the asset's HLS prefix.
type StoredObject struct {
	Path   string
	SHA256 [32]byte
	Size   int64
}

// RenditionInput is what Build needs to know about one rendition. Segments are in playlist order.
type RenditionInput struct {
	Name          string
	Width, Height int
	Bandwidth     int64
	Init          StoredObject
	Segments      []StoredObject
	Playlist      StoredObject
}

// Input is everything Build needs. Renditions are in ladder order.
type Input struct {
	AssetID, TenantID string
	CreatedAt         time.Time
	PipelineVersion   string
	Encoder           Encoder
	Renditions        []RenditionInput
	Master            StoredObject
	Thumbnails        []Thumbnail // optional (ADR 0046)
	SourceSHA256      [32]byte
	SourceSize        int64
}

// Built is a manifest with its canonical encoding, which is what gets signed.
type Built struct {
	Manifest  Manifest
	Canonical []byte
	TopRoot   [32]byte
}

// Build assembles the manifest, computes the trees and encodes it canonically. It is
// deterministic: the same Input always gives the same bytes.
func Build(in Input) (*Built, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	var err error
	m := Manifest{
		Schema:          Schema,
		AssetID:         in.AssetID,
		TenantID:        in.TenantID,
		CreatedAt:       in.CreatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		PipelineVersion: in.PipelineVersion,
		Encoder:         in.Encoder,
		Source:          Source{SHA256: hex.EncodeToString(in.SourceSHA256[:]), Size: in.SourceSize},
	}
	m.Encoder.Rungs = append([]Rung(nil), in.Encoder.Rungs...)
	if in.Encoder.Logo != nil {
		l := *in.Encoder.Logo
		m.Encoder.Logo = &l
	}

	t := buildTree(in.Renditions, in.Master)
	m.Renditions, m.Artifacts, m.TopLevel = t.renditions, t.artifacts, t.top
	if m.Thumbnails, err = thumbnailList(in.Thumbnails); err != nil {
		return nil, err
	}

	canonical, err := jcs.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("manifest: encode: %w", err)
	}
	return &Built{Manifest: m, Canonical: canonical, TopRoot: t.root}, nil
}

// tree is the renditions, playlists and top-level tree of one variant.
type tree struct {
	renditions []Rendition
	artifacts  []Artifact
	top        TopLevel
	root       merkle.Hash
}

// buildTree computes one tree per rendition and the top-level tree over them.
func buildTree(renditions []RenditionInput, master StoredObject) tree {
	var t tree
	var topLeaves, playlistLeaves []merkle.Hash
	var order, playlistOrder []string
	var playlists []Artifact
	for _, r := range renditions {
		leaves := make([]merkle.Hash, 0, 1+len(r.Segments))
		leaves = append(leaves, merkle.HashLeaf(r.Init.SHA256[:]))
		segs := make([]Object, 0, len(r.Segments))
		for _, s := range r.Segments {
			leaves = append(leaves, merkle.HashLeaf(s.SHA256[:]))
			segs = append(segs, object(s))
		}
		root := merkle.RootOf(leaves)
		t.renditions = append(t.renditions, Rendition{
			Name: r.Name, Width: r.Width, Height: r.Height, Bandwidth: r.Bandwidth,
			SegmentCount: len(r.Segments), Init: object(r.Init), Segments: segs,
			MerkleRoot: hex.EncodeToString(root[:]),
		})
		topLeaves = append(topLeaves, merkle.HashLeaf(root[:]))
		order = append(order, "rendition:"+r.Name)

		playlists = append(playlists, Artifact{
			Kind: KindPlaylist, Rendition: r.Name, Path: r.Playlist.Path,
			SHA256: hex.EncodeToString(r.Playlist.SHA256[:]), Size: r.Playlist.Size,
		})
		playlistLeaves = append(playlistLeaves, merkle.HashLeaf(r.Playlist.SHA256[:]))
		playlistOrder = append(playlistOrder, "playlist:"+r.Name)
	}
	t.artifacts = append([]Artifact{{
		Kind: KindMaster, Path: master.Path, SHA256: hex.EncodeToString(master.SHA256[:]), Size: master.Size,
	}}, playlists...)
	topLeaves = append(topLeaves, merkle.HashLeaf(master.SHA256[:]))
	order = append(order, "master")
	topLeaves = append(topLeaves, playlistLeaves...)
	order = append(order, playlistOrder...)

	t.root = merkle.RootOf(topLeaves)
	t.top = TopLevel{Order: order, Root: hex.EncodeToString(t.root[:])}
	return t
}

// MaskedInput is what WithMasked needs about the masked variant. Renditions are in ladder order.
type MaskedInput struct {
	CreatedAt     time.Time
	FacesDetected int
	Frames        int
	Rungs         []Rung
	Renditions    []RenditionInput
	Master        StoredObject
	Thumbnails    []Thumbnail // optional (ADR 0046)
	Logo          *Logo       // optional (ADR 0049)
}

// WithMasked returns m with its masked section set (replacing an earlier one) and the new canonical
// encoding, which is what gets signed again. Every other member is carried over unchanged, so the
// original variant's trees and hashes stay as they were signed. TopRoot stays the original
// variant's top-level root; the masked variant's is in Manifest.Masked.TopLevel.
func WithMasked(m Manifest, in MaskedInput) (*Built, error) {
	if in.CreatedAt.IsZero() || in.FacesDetected < 0 || in.Frames < 0 {
		return nil, errors.New("manifest: the masked section needs a time and non-negative counts")
	}
	if err := validateRenditions(in.Renditions, in.Master); err != nil {
		return nil, err
	}
	var top merkle.Hash
	raw, err := hex.DecodeString(m.TopLevel.Root)
	if err != nil || len(raw) != len(top) {
		return nil, errors.New("manifest: the original top-level root is malformed")
	}
	copy(top[:], raw)

	thumbs, err := thumbnailList(in.Thumbnails)
	if err != nil {
		return nil, err
	}
	t := buildTree(in.Renditions, in.Master)
	m.Masked = &Masked{
		CreatedAt:     in.CreatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		FacesDetected: in.FacesDetected, Frames: in.Frames, Rungs: append([]Rung(nil), in.Rungs...),
		Renditions: t.renditions, Artifacts: t.artifacts, TopLevel: t.top, Thumbnails: thumbs, Logo: in.Logo,
	}
	canonical, err := jcs.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("manifest: encode: %w", err)
	}
	return &Built{Manifest: m, Canonical: canonical, TopRoot: top}, nil
}

func object(o StoredObject) Object {
	return Object{Path: o.Path, SHA256: hex.EncodeToString(o.SHA256[:]), Size: o.Size}
}

func validate(in Input) error {
	switch {
	case in.AssetID == "" || in.TenantID == "":
		return errors.New("manifest: asset and tenant ids are required")
	case in.CreatedAt.IsZero():
		return errors.New("manifest: creation time is required")
	case in.SourceSize < 1:
		return errors.New("manifest: source size is required")
	}
	return validateRenditions(in.Renditions, in.Master)
}

func validateRenditions(renditions []RenditionInput, master StoredObject) error {
	if len(renditions) == 0 {
		return errors.New("manifest: at least one rendition is required")
	}
	if err := checkObject("master playlist", master); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range renditions {
		if r.Name == "" || strings.Contains(r.Name, ":") || seen[r.Name] {
			return errors.New("manifest: rendition names must be unique, non-empty and without ':'")
		}
		seen[r.Name] = true
		if len(r.Segments) == 0 {
			return fmt.Errorf("manifest: rendition %s has no segments", r.Name)
		}
		if err := checkObject("init segment", r.Init); err != nil {
			return err
		}
		if err := checkObject("media playlist", r.Playlist); err != nil {
			return err
		}
		for _, s := range r.Segments {
			if err := checkObject("segment", s); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkObject rejects a path that is not relative to the HLS prefix: the manifest never carries
// an object key.
func checkObject(what string, o StoredObject) error {
	p := o.Path
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "t/") || strings.Contains(p, "//") ||
		strings.Contains(p, "..") || strings.ContainsAny(p, "\\\x00") {
		return fmt.Errorf("manifest: %s has an invalid path", what)
	}
	if o.Size < 0 {
		return fmt.Errorf("manifest: %s has a negative size", what)
	}
	return nil
}
