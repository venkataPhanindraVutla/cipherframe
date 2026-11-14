// Package proof builds and checks two-level inclusion proofs for the artifacts of a signed
// manifest (ADR 0039).
//
// An init or media segment is proven in its rendition's tree, and that tree's root is proven in
// the top-level tree; a playlist is a leaf of the top-level tree only. Proofs are computed from the
// decoded manifest, never from storage, using the manifest's recorded order (ladder order, playlist
// order and top_level.order), so a proof is exactly what the signature covers.
//
// [Verify] checks a proof against a file hash and is self-contained: it proves that the hash is
// under TopLevel.Root. The caller must still compare that root with the signed manifest's.
package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/merkle"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
)

// Variants.
const (
	Original = "original"
	Masked   = "masked"
)

// Errors that are not integrity verdicts.
var (
	// ErrNotFound means the manifest has no artifact with the requested path.
	ErrNotFound = errors.New("proof: no such artifact in the manifest")
	// ErrNoVariant means the manifest has no section for the requested variant.
	ErrNoVariant = errors.New("proof: the manifest has no such variant")
)

// Level is the second level of a proof: a leaf in the top-level tree.
type Level struct {
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	AuditPath []string `json:"audit_path"`
	Root      string   `json:"root"`
}

// Proof proves that the artifact at Path of Variant is covered by the manifest's top-level root.
// For a playlist the rendition fields are absent and only TopLevel is present. Hashes are
// lowercase hex.
type Proof struct {
	AssetID string `json:"asset_id"`
	Variant string `json:"variant"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`

	LeafIndex     *uint64  `json:"leaf_index,omitempty"`
	TreeSize      *uint64  `json:"tree_size,omitempty"`
	Rendition     string   `json:"rendition,omitempty"`
	RenditionRoot string   `json:"rendition_root,omitempty"`
	AuditPath     []string `json:"audit_path,omitempty"`

	TopLevel Level `json:"top_level"`
}

// section is the part of a manifest that one variant's proofs come from.
type section struct {
	renditions []manifest.Rendition
	artifacts  []manifest.Artifact
	top        manifest.TopLevel
}

func sectionOf(m manifest.Manifest, variant string) (section, error) {
	switch variant {
	case Original:
		return section{m.Renditions, m.Artifacts, m.TopLevel}, nil
	case Masked:
		if m.Masked == nil {
			return section{}, ErrNoVariant
		}
		return section{m.Masked.Renditions, m.Masked.Artifacts, m.Masked.TopLevel}, nil
	}
	return section{}, fmt.Errorf("%w: unknown variant %q", ErrNoVariant, variant)
}

func decode(what, h string) (merkle.Hash, error) {
	var out merkle.Hash
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != len(out) || h != strings.ToLower(h) {
		return out, fmt.Errorf("%w: %s is not a 64-digit lowercase hex hash", verify.ErrMalformed, what)
	}
	copy(out[:], b)
	return out, nil
}

func encode(hs []merkle.Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = hex.EncodeToString(h[:])
	}
	return out
}

// Build returns the proof for the artifact at path in the given variant of m. It returns
// ErrNotFound for an unknown path and ErrNoVariant when m has no section for the variant; any
// other error (a manifest whose trees do not match its recorded roots) wraps verify.ErrMalformed.
func Build(m manifest.Manifest, variant, path string) (*Proof, error) {
	s, err := sectionOf(m, variant)
	if err != nil {
		return nil, err
	}
	p := &Proof{AssetID: m.AssetID, Variant: variant, Path: path}
	var label string
	for _, r := range s.renditions {
		objs := append([]manifest.Object{r.Init}, r.Segments...)
		i := slices.IndexFunc(objs, func(o manifest.Object) bool { return o.Path == path })
		if i < 0 {
			continue
		}
		leaves := make([]merkle.Hash, len(objs))
		for j, o := range objs {
			h, err := decode("an artifact hash", o.SHA256)
			if err != nil {
				return nil, err
			}
			leaves[j] = merkle.HashLeaf(h[:])
		}
		root := merkle.RootOf(leaves)
		if hex.EncodeToString(root[:]) != r.MerkleRoot {
			return nil, fmt.Errorf("%w: rendition %q does not match its recorded root", verify.ErrMalformed, r.Name)
		}
		ap, err := merkle.InclusionProof(leaves, uint64(i))
		if err != nil {
			return nil, err
		}
		idx, size := uint64(i), uint64(len(leaves))
		p.SHA256, p.Size = objs[i].SHA256, objs[i].Size
		p.LeafIndex, p.TreeSize, p.Rendition, p.RenditionRoot, p.AuditPath = &idx, &size, r.Name, r.MerkleRoot, encode(ap)
		label = "rendition:" + r.Name
		break
	}
	if label == "" {
		for _, a := range s.artifacts {
			if a.Path != path {
				continue
			}
			p.SHA256, p.Size = a.SHA256, a.Size
			label = "master"
			if a.Kind == manifest.KindPlaylist {
				label = "playlist:" + a.Rendition
			}
			break
		}
	}
	if label == "" {
		return nil, ErrNotFound
	}
	p.TopLevel, err = topLevel(s, label)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// topLevel proves the leaf with the given label in the top-level tree, taking the leaves in the
// manifest's recorded order.
func topLevel(s section, label string) (Level, error) {
	leaves := make([]merkle.Hash, len(s.top.Order))
	index := -1
	for i, l := range s.top.Order {
		data, err := topLeafData(s, l)
		if err != nil {
			return Level{}, err
		}
		leaves[i] = merkle.HashLeaf(data[:])
		if l == label {
			index = i
		}
	}
	root := merkle.RootOf(leaves)
	if index < 0 || hex.EncodeToString(root[:]) != s.top.Root {
		return Level{}, fmt.Errorf("%w: the top-level tree does not match its recorded root", verify.ErrMalformed)
	}
	ap, err := merkle.InclusionProof(leaves, uint64(index))
	if err != nil {
		return Level{}, err
	}
	return Level{LeafIndex: uint64(index), TreeSize: uint64(len(leaves)), AuditPath: encode(ap), Root: s.top.Root}, nil
}

// topLeafData is the data of a top-level leaf: a rendition's Merkle root, or a playlist's hash.
func topLeafData(s section, label string) (merkle.Hash, error) {
	kind, name, _ := strings.Cut(label, ":")
	switch kind {
	case "rendition":
		for _, r := range s.renditions {
			if r.Name == name {
				return decode("a rendition root", r.MerkleRoot)
			}
		}
	case "master", "playlist":
		for _, a := range s.artifacts {
			if (kind == "master" && a.Kind == manifest.KindMaster) || (kind == "playlist" && a.Kind == manifest.KindPlaylist && a.Rendition == name) {
				return decode("a playlist hash", a.SHA256)
			}
		}
	}
	return merkle.Hash{}, fmt.Errorf("%w: top-level leaf %q has no artifact", verify.ErrMalformed, label)
}

// Verify checks that sum (the SHA-256 of the artifact's bytes) is under p.TopLevel.Root: through
// the rendition tree when the proof has one, then through the top-level tree. A hash that differs
// from p.SHA256 or a path that leads to another root wraps verify.ErrTampered; a proof that cannot
// belong to any tree wraps verify.ErrMalformed.
func Verify(p Proof, sum [sha256.Size]byte) error {
	if hex.EncodeToString(sum[:]) != p.SHA256 {
		return fmt.Errorf("%w: the hash differs from the one in the proof", verify.ErrTampered)
	}
	leaf := merkle.HashLeaf(sum[:])
	if p.RenditionRoot != "" {
		if p.LeafIndex == nil || p.TreeSize == nil {
			return fmt.Errorf("%w: rendition level without leaf_index or tree_size", verify.ErrMalformed)
		}
		root, err := decode("rendition_root", p.RenditionRoot)
		if err != nil {
			return err
		}
		path, err := decodeAll(p.AuditPath)
		if err != nil {
			return err
		}
		if err := merkle.VerifyInclusion(leaf, *p.LeafIndex, *p.TreeSize, path, root); err != nil {
			return err
		}
		leaf = merkle.HashLeaf(root[:])
	} else if p.LeafIndex != nil || p.TreeSize != nil || len(p.AuditPath) > 0 {
		return fmt.Errorf("%w: rendition fields without rendition_root", verify.ErrMalformed)
	}
	top, err := decode("top_level.root", p.TopLevel.Root)
	if err != nil {
		return err
	}
	path, err := decodeAll(p.TopLevel.AuditPath)
	if err != nil {
		return err
	}
	return merkle.VerifyInclusion(leaf, p.TopLevel.LeafIndex, p.TopLevel.TreeSize, path, top)
}

func decodeAll(hs []string) ([]merkle.Hash, error) {
	out := make([]merkle.Hash, len(hs))
	for i, h := range hs {
		var err error
		if out[i], err = decode("an audit path element", h); err != nil {
			return nil, err
		}
	}
	return out, nil
}
