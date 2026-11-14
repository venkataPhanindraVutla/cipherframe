package deletion

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func input() Input {
	return Input{
		AssetID: "ast_00000000000000000000000001", TenantID: "ten_00000000000000000000000001",
		RequestedAt: time.Date(2026, 11, 14, 10, 0, 0, 900, time.UTC), CompletedAt: time.Date(2026, 11, 14, 10, 0, 7, 0, time.UTC),
		Reason: ReasonRequested, PipelineVersion: "v1.2.3",
		Objects: []ObjectCount{
			{Bucket: "source", Kind: "source", Count: 1, Bytes: 1000},
			{Bucket: "delivery", Kind: "segment", Variant: "original", Count: 3, Bytes: 300},
			{Bucket: "delivery", Kind: "segment", Variant: "masked", Count: 3, Bytes: 310},
			{Bucket: "delivery", Kind: "master", Variant: "original", Count: 1, Bytes: 10},
		},
		Keys:         []KeyRef{{ID: "cky_b", Variant: "masked"}, {ID: "cky_a", Variant: "original"}},
		ManifestRoot: bytes.Repeat([]byte{0xab}, 32),
	}
}

func TestBuildIsCanonicalSortedAndTotalled(t *testing.T) {
	b, err := Build(input())
	if err != nil {
		t.Fatal(err)
	}
	r := b.Record
	if r.ObjectsDeleted != 8 || r.BytesDeleted != 1620 || r.ContentKeys.Destroyed != 2 || r.ContentKeys.Keys[0].ID != "cky_a" {
		t.Fatalf("record = %+v", r)
	}
	if r.RequestedAt != "2026-11-14T10:00:00Z" || r.CompletedAt != "2026-11-14T10:00:07Z" {
		t.Fatalf("times = %s %s", r.RequestedAt, r.CompletedAt)
	}
	if got := r.Objects[0]; got.Bucket != "delivery" || got.Kind != "master" {
		t.Fatalf("objects are not sorted: %+v", r.Objects)
	}
	// Members are sorted and there is no whitespace.
	want := `{"asset_id":"ast_00000000000000000000000001","bytes_deleted":1620,"completed_at":"2026-11-14T10:00:07Z","content_keys":`
	if !strings.HasPrefix(string(b.Canonical), want) || strings.ContainsAny(string(b.Canonical), " \n") {
		t.Fatalf("canonical form = %s", b.Canonical)
	}
	// The same input in another order gives the same bytes.
	in := input()
	in.Objects[0], in.Objects[3] = in.Objects[3], in.Objects[0]
	in.Keys[0], in.Keys[1] = in.Keys[1], in.Keys[0]
	b2, err := Build(in)
	if err != nil || !bytes.Equal(b.Canonical, b2.Canonical) {
		t.Fatalf("not deterministic: %v", err)
	}
	back, err := Parse(b.Canonical)
	if err != nil || back.AssetID != r.AssetID || back.ManifestRoot != strings.Repeat("ab", 32) {
		t.Fatalf("Parse = %+v, %v", back, err)
	}
}

func TestBuildWithoutManifestOrObjects(t *testing.T) {
	in := input()
	in.ManifestRoot, in.Objects, in.Keys = nil, nil, nil
	b, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b.Canonical), "manifest_root") || !strings.Contains(string(b.Canonical), `"objects":[]`) ||
		!strings.Contains(string(b.Canonical), `"keys":[]`) {
		t.Fatalf("canonical form = %s", b.Canonical)
	}
}

func TestBuildRejectsBadInput(t *testing.T) {
	for name, mut := range map[string]func(*Input){
		"no asset":        func(i *Input) { i.AssetID = "" },
		"bad reason":      func(i *Input) { i.Reason = "because" },
		"times reversed":  func(i *Input) { i.CompletedAt = i.RequestedAt.Add(-time.Second) },
		"no version":      func(i *Input) { i.PipelineVersion = "" },
		"short root":      func(i *Input) { i.ManifestRoot = []byte{1} },
		"empty count":     func(i *Input) { i.Objects[0].Count = 0 },
		"repeated count":  func(i *Input) { i.Objects = append(i.Objects, i.Objects[0]) },
		"incomplete key":  func(i *Input) { i.Keys[0].Variant = "" },
		"negative bytes":  func(i *Input) { i.Objects[0].Bytes = -1 },
		"missing bucket":  func(i *Input) { i.Objects[0].Bucket = "" },
		"zero completion": func(i *Input) { i.CompletedAt = time.Time{} },
	} {
		in := input()
		mut(&in)
		if _, err := Build(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseIsStrict(t *testing.T) {
	good, _ := Build(input())
	for name, doc := range map[string]string{
		"unknown member": strings.Replace(string(good.Canonical), `{"asset_id"`, `{"extra":1,"asset_id"`, 1),
		"wrong schema":   strings.Replace(string(good.Canonical), Schema, "cipherframe.manifest/v1", 1),
		"trailing":       string(good.Canonical) + `{}`,
		"not json":       "nope",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
