package contentkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
)

func binding() Binding {
	return Binding{
		EnvelopeVersion: EnvelopeVersion,
		AssetID:         id.New[id.AssetKind](),
		ContentKeyID:    id.New[id.ContentKeyKind](),
		Provider:        "local",
		KEKKeyID:        "local",
		KEKVersion:      "1",
	}
}

func provider(t *testing.T) *local.Provider {
	t.Helper()
	p, err := local.NewFromKeys(config.Development, map[int][]byte{
		1: bytes.Repeat([]byte{0x31}, config.KEKBytes),
	}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAAD(t *testing.T) {
	b := binding()
	if !bytes.Equal(AAD(b), AAD(b)) {
		t.Fatal("AAD is not deterministic")
	}
	if got := AAD(b); got[0] != EnvelopeVersion {
		t.Fatal("the first byte must be the envelope version")
	}
	if AAD(Binding{}) != nil {
		t.Fatal("an envelope version of zero must not encode")
	}
	b.EnvelopeVersion = 256
	if AAD(b) != nil {
		t.Fatal("an envelope version above 255 must not encode")
	}
}

// TestAADBindsEveryField wraps a key under one binding and shows that changing any single field of
// the binding makes the unwrap fail with ErrInvalid.
func TestAADBindsEveryField(t *testing.T) {
	ctx := context.Background()
	p := provider(t)
	orig := binding()
	key := bytes.Repeat([]byte{0x5a}, KeyBytes)
	w, err := p.Wrap(ctx, key, AAD(orig))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.Unwrap(ctx, w, AAD(orig)); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("the original binding must unwrap: %v", err)
	}

	tests := []struct {
		name   string
		change func(*Binding)
	}{
		{"envelope version", func(b *Binding) { b.EnvelopeVersion = 2 }},
		{"asset id", func(b *Binding) { b.AssetID = id.New[id.AssetKind]() }},
		{"content key id", func(b *Binding) { b.ContentKeyID = id.New[id.ContentKeyKind]() }},
		{"provider", func(b *Binding) { b.Provider = "vault" }},
		{"kek key id", func(b *Binding) { b.KEKKeyID = "other" }},
		{"kek version", func(b *Binding) { b.KEKVersion = "2" }},
		{"asset id zeroed", func(b *Binding) { b.AssetID = id.AssetID{} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			changed := orig
			tc.change(&changed)
			if bytes.Equal(AAD(changed), AAD(orig)) {
				t.Fatal("the AAD did not change")
			}
			got, err := p.Unwrap(ctx, w, AAD(changed))
			if !errors.Is(err, kms.ErrInvalid) || got != nil {
				t.Fatalf("want ErrInvalid and no key, got %v", err)
			}
		})
	}
}

// TestAADIsUnambiguous shows that moving bytes between adjacent fields changes the encoding.
func TestAADIsUnambiguous(t *testing.T) {
	a := binding()
	b := a
	a.Provider, a.KEKKeyID = "ab", "c"
	b.Provider, b.KEKKeyID = "a", "bc"
	if bytes.Equal(AAD(a), AAD(b)) {
		t.Fatal("different field splits encode identically")
	}
	a.KEKKeyID, a.KEKVersion = "x", "yz"
	b = a
	b.KEKKeyID, b.KEKVersion = "xy", "z"
	if bytes.Equal(AAD(a), AAD(b)) {
		t.Fatal("different field splits encode identically")
	}
}

func TestContentKeyRedaction(t *testing.T) {
	raw := []byte("0123456789abcdef")
	k := newContentKey(id.New[id.ContentKeyKind](), id.New[id.AssetKind](), raw)
	if !bytes.Equal(k.Bytes(), raw) {
		t.Fatal("Bytes must return the key")
	}

	type holder struct {
		Key  ContentKey
		priv ContentKey
	}
	h := holder{Key: k, priv: k}

	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
		outs = append(outs, fmt.Sprintf(verb, k), fmt.Sprintf(verb, &k), fmt.Sprintf(verb, h), fmt.Sprintf(verb, &h),
			fmt.Sprintf(verb, []ContentKey{k}), fmt.Sprintf(verb, map[string]ContentKey{"k": k}))
	}
	j, err := json.Marshal(map[string]any{"k": k, "h": h})
	if err != nil {
		t.Fatal(err)
	}
	outs = append(outs, string(j))
	tx, err := k.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	bin, err := k.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	outs = append(outs, string(tx), string(bin), k.String(), k.GoString())
	var jb, tb bytes.Buffer
	slog.New(slog.NewJSONHandler(&jb, nil)).Info("k", "key", k, "holder", h)
	slog.New(slog.NewTextHandler(&tb, nil)).Info("k", "key", k, slog.Any("holder", &h))
	outs = append(outs, jb.String(), tb.String())

	forms := []string{
		string(raw), hex.EncodeToString(raw), strings.ToUpper(hex.EncodeToString(raw)),
		base64.StdEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw),
		fmt.Sprint(raw), fmt.Sprintf("%v", []byte(raw)),
	}
	for _, o := range outs {
		for _, f := range forms {
			if strings.Contains(o, f) {
				t.Fatalf("key bytes appear in printed output: %.40q", o)
			}
		}
	}
	if !strings.Contains(fmt.Sprintf("%v", k), Redacted) {
		t.Fatal("a printed key should say it is redacted")
	}
}

func TestContentKeyIsolationAndZero(t *testing.T) {
	raw := []byte("0123456789abcdef")
	k := newContentKey(id.New[id.ContentKeyKind](), id.New[id.AssetKind](), raw)
	raw[0] = 'X' // the input slice is copied
	if k.Bytes()[0] != '0' {
		t.Fatal("ContentKey must copy its input")
	}
	b := k.Bytes()
	b[0] = 'Y' // mutating a returned copy must not change the key
	if k.Bytes()[0] != '0' {
		t.Fatal("Bytes must return a copy")
	}
	k.Zero()
	if !bytes.Equal(k.Bytes(), make([]byte, len(raw))) {
		t.Fatal("Zero must clear the key")
	}
	var zero ContentKey
	if !zero.IsZero() || zero.Bytes() != nil {
		t.Fatal("the zero ContentKey holds nothing")
	}
	zero.Zero() // must not panic
}
