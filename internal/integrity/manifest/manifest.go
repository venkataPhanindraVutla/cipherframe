package manifest

import (
	"encoding/hex"
	"errors"
	"fmt"
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
}

// Rung is the encoder setting of one rendition.
type Rung struct {
	Name        string `json:"name"`
	CRF         int    `json:"crf"`
	MaxrateKbps int    `json:"maxrate_kbps"`
	BufsizeKbps int    `json:"bufsize_kbps"`
	AudioKbps   int    `json:"audio_kbps"`
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

	var topLeaves, playlistLeaves []merkle.Hash
	var order, playlistOrder []string
	var playlists []Artifact
	for _, r := range in.Renditions {
		leaves := make([]merkle.Hash, 0, 1+len(r.Segments))
		leaves = append(leaves, merkle.HashLeaf(r.Init.SHA256[:]))
		segs := make([]Object, 0, len(r.Segments))
		for _, s := range r.Segments {
			leaves = append(leaves, merkle.HashLeaf(s.SHA256[:]))
			segs = append(segs, object(s))
		}
		root := merkle.RootOf(leaves)
		m.Renditions = append(m.Renditions, Rendition{
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
	m.Artifacts = append([]Artifact{{
		Kind: KindMaster, Path: in.Master.Path, SHA256: hex.EncodeToString(in.Master.SHA256[:]), Size: in.Master.Size,
	}}, playlists...)
	topLeaves = append(topLeaves, merkle.HashLeaf(in.Master.SHA256[:]))
	order = append(order, "master")
	topLeaves = append(topLeaves, playlistLeaves...)
	order = append(order, playlistOrder...)

	top := merkle.RootOf(topLeaves)
	m.TopLevel = TopLevel{Order: order, Root: hex.EncodeToString(top[:])}

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
	case len(in.Renditions) == 0:
		return errors.New("manifest: at least one rendition is required")
	}
	if err := checkObject("master playlist", in.Master); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range in.Renditions {
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
