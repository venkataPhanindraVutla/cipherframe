// Package deletion is the signed deletion record (M6-3, ADR 0033, ADR 0040). When the purge job has
// removed every object of an asset, destroyed its content keys and verified that storage is empty,
// it writes one of these: a canonical JSON document (RFC 8785) wrapped in a DSSE envelope with
// payload type [PayloadType], signed with the same keys that sign manifests.
//
// The record names counts, sizes, key IDs and times. It never holds object keys, bucket names,
// key material or a viewer's data. Like the manifest package it depends only on the standard
// library and the other integrity packages, so an offline verifier can use it.
package deletion

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/jcs"
)

const (
	// Schema identifies this version of the format.
	Schema = "cipherframe.deletion/v1"
	// PayloadType is the DSSE payload type of a signed deletion record.
	PayloadType = "application/vnd.cipherframe.deletion+json"
)

// Reasons a deletion happened.
const (
	ReasonRequested = "requested"
	ReasonRetention = "retention"
)

// Record is the document that is signed. Its JSON encoding is canonical (see Build).
type Record struct {
	Schema      string `json:"schema"`
	AssetID     string `json:"asset_id"`
	TenantID    string `json:"tenant_id"`
	RequestedAt string `json:"requested_at"`
	CompletedAt string `json:"completed_at"`
	Reason      string `json:"reason"`
	// PipelineVersion is the Cipherframe version that ran the purge.
	PipelineVersion string `json:"pipeline_version"`
	// Objects counts what was deleted per bucket, artifact kind and variant, sorted by those.
	Objects []ObjectCount `json:"objects"`
	// ObjectsDeleted and BytesDeleted are the totals of Objects.
	ObjectsDeleted int64 `json:"objects_deleted"`
	BytesDeleted   int64 `json:"bytes_deleted"`
	// ContentKeys names the destroyed content keys (never key material).
	ContentKeys ContentKeys `json:"content_keys"`
	// ManifestRoot is the top-level Merkle root (hex) of the asset's integrity manifest as it
	// stood at deletion, absent when the asset never had one.
	ManifestRoot string `json:"manifest_root,omitempty"`
}

// ObjectCount is the number of objects and bytes deleted of one kind. Bucket is the role
// ("source" or "delivery"); Variant is "original" or "masked" for HLS objects and absent otherwise.
type ObjectCount struct {
	Bucket  string `json:"bucket"`
	Kind    string `json:"kind"`
	Variant string `json:"variant,omitempty"`
	Count   int64  `json:"count"`
	Bytes   int64  `json:"bytes"`
}

// ContentKeys lists the destroyed keys.
type ContentKeys struct {
	Destroyed int      `json:"destroyed"`
	Keys      []KeyRef `json:"keys"`
}

// KeyRef names one destroyed content key: its ID and the variant it protected.
type KeyRef struct {
	ID      string `json:"id"`
	Variant string `json:"variant"`
}

// Input is what Build needs.
type Input struct {
	AssetID, TenantID string
	RequestedAt       time.Time
	CompletedAt       time.Time
	Reason            string
	PipelineVersion   string
	Objects           []ObjectCount
	Keys              []KeyRef
	// ManifestRoot is the manifest's top-level root as 32 bytes, or nil.
	ManifestRoot []byte
}

// Built is a record with its canonical encoding, which is what gets signed.
type Built struct {
	Record    Record
	Canonical []byte
}

// Build validates in, computes the totals and encodes the record canonically. It is
// deterministic: equal inputs (in any order of Objects and Keys) give the same bytes.
func Build(in Input) (*Built, error) {
	switch {
	case in.AssetID == "" || in.TenantID == "":
		return nil, errors.New("deletion: the record needs an asset and a tenant")
	case in.Reason != ReasonRequested && in.Reason != ReasonRetention:
		return nil, fmt.Errorf("deletion: unknown reason %q", in.Reason)
	case in.RequestedAt.IsZero() || in.CompletedAt.IsZero() || in.CompletedAt.Before(in.RequestedAt):
		return nil, errors.New("deletion: the times are missing or out of order")
	case in.PipelineVersion == "":
		return nil, errors.New("deletion: the pipeline version is required")
	case len(in.ManifestRoot) != 0 && len(in.ManifestRoot) != 32:
		return nil, errors.New("deletion: the manifest root must be 32 bytes")
	}
	r := Record{
		Schema: Schema, AssetID: in.AssetID, TenantID: in.TenantID,
		RequestedAt: in.RequestedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		CompletedAt: in.CompletedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		Reason:      in.Reason, PipelineVersion: in.PipelineVersion,
		Objects:     slices.Clone(in.Objects),
		ContentKeys: ContentKeys{Keys: slices.Clone(in.Keys)},
	}
	if r.Objects == nil {
		r.Objects = []ObjectCount{}
	}
	if r.ContentKeys.Keys == nil {
		r.ContentKeys.Keys = []KeyRef{}
	}
	slices.SortFunc(r.Objects, func(a, b ObjectCount) int {
		return strings.Compare(a.Bucket+"\x00"+a.Kind+"\x00"+a.Variant, b.Bucket+"\x00"+b.Kind+"\x00"+b.Variant)
	})
	for i, o := range r.Objects {
		if o.Bucket == "" || o.Kind == "" || o.Count < 1 || o.Bytes < 0 ||
			(i > 0 && r.Objects[i-1].Bucket == o.Bucket && r.Objects[i-1].Kind == o.Kind && r.Objects[i-1].Variant == o.Variant) {
			return nil, errors.New("deletion: an object count is empty or repeated")
		}
		r.ObjectsDeleted += o.Count
		r.BytesDeleted += o.Bytes
	}
	slices.SortFunc(r.ContentKeys.Keys, func(a, b KeyRef) int { return strings.Compare(a.ID, b.ID) })
	for _, k := range r.ContentKeys.Keys {
		if k.ID == "" || k.Variant == "" {
			return nil, errors.New("deletion: a content key reference is incomplete")
		}
	}
	r.ContentKeys.Destroyed = len(r.ContentKeys.Keys)
	if len(in.ManifestRoot) == 32 {
		r.ManifestRoot = fmt.Sprintf("%x", in.ManifestRoot)
	}
	canonical, err := jcs.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("deletion: encode: %w", err)
	}
	return &Built{Record: r, Canonical: canonical}, nil
}

// Parse decodes a record payload. It is strict: unknown members and trailing data are errors, and
// the schema must be [Schema]. It does not check any signature.
func Parse(payload []byte) (Record, error) {
	var r Record
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Record{}, fmt.Errorf("deletion: the payload is not a deletion record: %w", err)
	}
	if dec.More() {
		return Record{}, errors.New("deletion: trailing data after the record")
	}
	if r.Schema != Schema {
		return Record{}, fmt.Errorf("deletion: the payload is not a %s record", Schema)
	}
	return r, nil
}
