package id

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"uuid"
)

func roundTrip[K Kind](t *testing.T, prefix string) {
	t.Helper()
	a := New[K]()
	s := a.String()
	if len(s) != len(prefix)+1+26 || !strings.HasPrefix(s, prefix+"_") {
		t.Fatalf("unexpected text form %q", s)
	}
	b, err := Parse[K](s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	if a != b || b.UUID() != a.UUID() {
		t.Fatalf("round trip mismatch: %v vs %v", a, b)
	}
	if FromUUID[K](a.UUID()) != a {
		t.Fatal("FromUUID mismatch")
	}
}

func TestRoundTripEveryKind(t *testing.T) {
	roundTrip[TenantKind](t, "ten")
	roundTrip[ClientKind](t, "cli")
	roundTrip[APIKeyKind](t, "key")
	roundTrip[AssetKind](t, "ast")
}

func TestWrongPrefixRejected(t *testing.T) {
	c := New[ClientKind]().String()
	if _, err := Parse[AssetKind](c); !errors.Is(err, ErrFormat) {
		t.Fatalf("want ErrFormat, got %v", err)
	}
	if _, err := Parse[AssetKind](strings.Replace(c, "cli", "ast", 1)); err != nil {
		t.Fatalf("swapped prefix should parse: %v", err)
	}
	if _, err := Parse[AssetKind]("ast-" + c[4:]); err == nil {
		t.Fatal("wrong separator accepted")
	}
}

func TestUppercaseRejected(t *testing.T) {
	s := New[AssetKind]().String()
	if _, err := Parse[AssetKind](strings.ToUpper(s)); err == nil {
		t.Fatal("uppercase accepted")
	}
	if _, err := Parse[AssetKind]("ast_" + strings.ToUpper(s[4:])); err == nil {
		t.Fatal("uppercase body accepted")
	}
}

func TestWrongLengthRejected(t *testing.T) {
	s := New[AssetKind]().String()
	for _, in := range []string{"", "ast_", s[:len(s)-1], s + "0", " " + s, s + "\n"} {
		if _, err := Parse[AssetKind](in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestBadAlphabetRejected(t *testing.T) {
	for _, c := range []string{"i", "l", "o", "u", "-", "="} {
		in := "ast_" + strings.Repeat("1", 25) + c
		if _, err := Parse[AssetKind](in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestNonCanonicalRejected(t *testing.T) {
	// 26 chars carry 130 bits; the last char's low 2 bits must be zero.
	if _, err := Parse[AssetKind]("ast_" + strings.Repeat("1", 25) + "1"); err == nil {
		t.Fatal("non-zero trailing bits accepted")
	}
	// Last char 'g' = 16 = 0b10000 has zero low bits and is canonical.
	if _, err := Parse[AssetKind]("ast_" + strings.Repeat("1", 25) + "g"); err != nil {
		t.Fatalf("canonical rejected: %v", err)
	}
}

func TestZeroAndNil(t *testing.T) {
	var z AssetID
	if !z.IsZero() || z.String() != "" {
		t.Fatal("zero ID misbehaves")
	}
	if _, err := z.MarshalText(); !errors.Is(err, ErrZero) {
		t.Fatalf("want ErrZero, got %v", err)
	}
	if _, err := json.Marshal(z); err == nil {
		t.Fatal("json marshalled zero ID")
	}
	if _, err := Parse[AssetKind]("ast_" + strings.Repeat("0", 26)); err == nil {
		t.Fatal("nil UUID text accepted")
	}
}

func TestErrorsDoNotEchoInput(t *testing.T) {
	in := "ast_SECRETSECRETSECRETSECRETSEC"
	_, err := Parse[AssetKind](in)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("bad error: %v", err)
	}
	_, err = ParseSession("ses_SECRET")
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("bad error: %v", err)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	type doc struct {
		Asset  AssetID         `json:"asset"`
		Client ClientID        `json:"client"`
		By     map[AssetID]int `json:"by"`
	}
	in := doc{Asset: New[AssetKind](), Client: New[ClientKind](), By: map[AssetID]int{New[AssetKind](): 1}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out doc
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Asset != in.Asset || out.Client != in.Client || len(out.By) != 1 {
		t.Fatalf("mismatch: %s", b)
	}
	if err := json.Unmarshal([]byte(`{"asset":"cli_`+strings.Repeat("1", 26)+`"}`), &out); err == nil {
		t.Fatal("wrong kind accepted via JSON")
	}
	before := out.Asset
	_ = json.Unmarshal([]byte(`{"asset":"bogus"}`), &out)
	if out.Asset != before {
		t.Fatal("failed unmarshal changed value")
	}
}

func TestSortOrderMatchesTextOrder(t *testing.T) {
	const n = 2000
	ids := make([]AssetID, n)
	for i := range ids {
		ids[i] = New[AssetKind]()
	}
	byUUID := sort.SliceIsSorted(ids, func(i, j int) bool { return ids[i].UUID().Compare(ids[j].UUID()) < 0 })
	byText := sort.SliceIsSorted(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	if !byUUID || !byText {
		t.Fatalf("sequential IDs not ordered: uuid=%v text=%v", byUUID, byText)
	}
}

func TestEncodingPreservesByteOrder(t *testing.T) {
	for range 5000 {
		a, b := uuid.New(), uuid.New()
		if a.Compare(b) != strings.Compare(encode(a[:]), encode(b[:])) {
			t.Fatalf("order mismatch for %v %v", a, b)
		}
	}
}

func TestEncodeKnownVectors(t *testing.T) {
	var maxv [16]byte
	for i := range maxv {
		maxv[i] = 0xff
	}
	if got := encode(maxv[:]); got != strings.Repeat("z", 25)+"w" {
		t.Fatalf("max = %q", got)
	}
	if got := encode(make([]byte, 16)); got != strings.Repeat("0", 26) {
		t.Fatalf("zero = %q", got)
	}
}
