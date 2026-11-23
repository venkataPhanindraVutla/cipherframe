package manifest

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/jcs"
)

// Rekeyed holds the objects one variant has after a content-key re-key (ADR 0068), by rendition
// name: the re-encrypted media segments in playlist order and the media playlists that carry their
// new IVs. Paths are relative to the variant's HLS prefix. Init segments and master playlist are not
// encrypted and are carried over as they were signed.
type Rekeyed struct {
	Segments  map[string][]StoredObject
	Playlists map[string]StoredObject
}

// WithRekeyed returns m with the segment and playlist hashes of the original variant, and of the
// masked variant when it has one, replaced by the re-keyed objects, and the new canonical encoding,
// which is what gets signed again. Every other member is carried over as signed. masked must be set
// exactly when m has a masked section. TopRoot is the original variant's new top-level root.
func WithRekeyed(m Manifest, orig Rekeyed, masked *Rekeyed) (*Built, error) {
	if (masked != nil) != (m.Masked != nil) {
		return nil, errors.New("manifest: the masked section and its re-keyed objects must go together")
	}
	t, err := retree(m.Renditions, m.Artifacts, orig)
	if err != nil {
		return nil, err
	}
	m.Renditions, m.Artifacts, m.TopLevel = t.renditions, t.artifacts, t.top
	if masked != nil {
		mm := *m.Masked
		mt, err := retree(mm.Renditions, mm.Artifacts, *masked)
		if err != nil {
			return nil, err
		}
		mm.Renditions, mm.Artifacts, mm.TopLevel = mt.renditions, mt.artifacts, mt.top
		m.Masked = &mm
	}
	canonical, err := jcs.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("manifest: encode: %w", err)
	}
	return &Built{Manifest: m, Canonical: canonical, TopRoot: t.root}, nil
}

// retree rebuilds one variant's trees from its signed renditions with the segments and playlists
// replaced.
func retree(renditions []Rendition, artifacts []Artifact, r Rekeyed) (tree, error) {
	var master StoredObject
	for _, a := range artifacts {
		if a.Kind == KindMaster {
			o, err := storedOf(a.Path, a.SHA256, a.Size)
			if err != nil {
				return tree{}, err
			}
			master = o
		}
	}
	in := make([]RenditionInput, 0, len(renditions))
	for _, old := range renditions {
		segs, pl := r.Segments[old.Name], r.Playlists[old.Name]
		if len(segs) != old.SegmentCount || pl.Path == "" {
			return tree{}, fmt.Errorf("manifest: no re-keyed objects for rendition %s", old.Name)
		}
		init, err := storedOf(old.Init.Path, old.Init.SHA256, old.Init.Size)
		if err != nil {
			return tree{}, err
		}
		in = append(in, RenditionInput{
			Name: old.Name, Width: old.Width, Height: old.Height, Bandwidth: old.Bandwidth,
			Init: init, Segments: segs, Playlist: pl,
		})
	}
	if err := validateRenditions(in, master); err != nil {
		return tree{}, err
	}
	return buildTree(in, master), nil
}

func storedOf(path, sha string, size int64) (StoredObject, error) {
	var o StoredObject
	raw, err := hex.DecodeString(sha)
	if err != nil || len(raw) != len(o.SHA256) {
		return o, errors.New("manifest: a signed object hash is malformed")
	}
	o.Path, o.Size = path, size
	copy(o.SHA256[:], raw)
	return o, nil
}
