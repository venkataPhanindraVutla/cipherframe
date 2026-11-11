package jcs

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
)

// RFC 8785 Appendix B: IEEE 754 bit patterns and the ECMAScript serialisation each must have.
// Reproduced from the RFC (the same table is in the cyberphone/json-canonicalization test data).
func TestRFC8785AppendixBNumbers(t *testing.T) {
	cases := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"}, // minus zero
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, tc := range cases {
		if got := FormatNumber(math.Float64frombits(tc.bits)); got != tc.want {
			t.Errorf("%016x: got %s want %s", tc.bits, got, tc.want)
		}
	}
}

func TestNumbersFromText(t *testing.T) {
	cases := map[string]string{
		"0": "0", "-0": "0", "-0.0": "0", "1E30": "1e+30", "4.50": "4.5", "2e-3": "0.002",
		"1e21": "1e+21", "1e20": "100000000000000000000", "123456789e-3": "123456.789",
		"0.0000001": "1e-7", "1e-400": "0", "-1.5e300": "-1.5e+300", "5E-324": "5e-324",
		"9007199254740991": "9007199254740991", "-9007199254740991": "-9007199254740991",
		"9007199254740993": "9007199254740992", "100000000000000000000": "100000000000000000000", // RFC 8785: rounds to a double
	}
	for in, want := range cases {
		got, err := Canonicalize([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s: got %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestRFC8785Section322Example(t *testing.T) {
	// RFC 8785 section 3.2.2 (and cyberphone testdata/input/values.json): number and string
	// serialisation, members sorted. 26 zeros after the decimal point give 1e-27.
	in := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.` + strings.Repeat("0", 26) + `1],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],` +
		"\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
	got, err := Canonicalize([]byte(in))
	if err != nil || string(got) != want {
		t.Fatalf("got %s, %v\nwant %s", got, err, want)
	}
}

func TestRFC8785Section323Sorting(t *testing.T) {
	// RFC 8785 section 3.2.3: names sort by UTF-16 code units, so U+1F600 (D83D DE00) sorts
	// before U+FB33 although its code point is larger.
	in := `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh",` +
		`"1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\"," +
		"\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\"," +
		"\"😀\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	got, err := Canonicalize([]byte(in))
	if err != nil || string(got) != want {
		t.Fatalf("got %q, %v\nwant %q", got, err, want)
	}
}

// Cases from the cyberphone/json-canonicalization test data (arrays, french, structures,
// unicode), reproduced as input/output pairs.
func TestCyberphoneVectors(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"arrays", `[56,{"d":true,"10":null,"1":[]}]`, `[56,{"1":[],"10":null,"d":true}]`},
		{
			"french",
			`{"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"ignore locale"}`,
			`{"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"ignore locale"}`,
		},
		{
			"structures",
			`{"1":{"f":{"f":"hi","F":5},"\n":56.0},"10":{},"":"empty","a":{},"111":[{"e":"yes","E":"no"}],"A":{}}`,
			`{"":"empty","1":{"\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}`,
		},
		{"unicode", "{\"Unnormalized Unicode\":\"A\u030a\"}", "{\"Unnormalized Unicode\":\"A\u030a\"}"},
	}
	for _, tc := range cases {
		got, err := Canonicalize([]byte(tc.in))
		if err != nil || string(got) != tc.want {
			t.Errorf("%s: got %s, %v\nwant %s", tc.name, got, err, tc.want)
		}
	}
}

func TestStringEscaping(t *testing.T) {
	cases := map[string]string{
		`"\u0000\u001f\u007f\u2028"`: "\"\\u0000\\u001f\u007f\u2028\"",
		`"\b\t\n\f\r\"\\\/"`:         `"\b\t\n\f\r\"\\/"`,
		`"\u00E9"`:                   "\"é\"",
		`"\uD83D\uDE00"`:             "\"😀\"",
		"\"\u00e9\"":                 "\"é\"",
	}
	for in, want := range cases {
		got, err := Canonicalize([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s: got %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestWhitespaceAndTopLevel(t *testing.T) {
	got, err := Canonicalize([]byte(" \t\r\n{ \"b\" : [ 1 , 2 ] , \"a\" : { } }\n"))
	if err != nil || string(got) != `{"a":{},"b":[1,2]}` {
		t.Fatalf("got %s, %v", got, err)
	}
	for in, want := range map[string]string{"null": "null", "true": "true", `"x"`: `"x"`, "[]": "[]", "{}": "{}"} {
		if got, err := Canonicalize([]byte(in)); err != nil || string(got) != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
}

func TestRejects(t *testing.T) {
	deep := strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1)
	cases := map[string]string{
		"empty":               ``,
		"duplicate":           `{"a":1,"a":2}`,
		"duplicate escaped":   `{"a":1,"\u0061":2}`,
		"invalid utf8":        "\"\xff\"",
		"invalid utf8 key":    "{\"\xc3\":1}",
		"lone high surrogate": `"\ud800"`,
		"lone low surrogate":  `"\udc00"`,
		"bad pair":            `"\ud800\u0041"`,
		"trailing":            `1 2`,
		"trailing comma":      `[1,]`,
		"trailing comma obj":  `{"a":1,}`,
		"leading zero":        `01`,
		"plus":                `+1`,
		"dot":                 `1.`,
		"exp":                 `1e`,
		"nan":                 `NaN`,
		"infinity":            `Infinity`,
		"overflow":            `1e999`,
		"single quotes":       `'a'`,
		"control in string":   "\"a\nb\"",
		"bad escape":          `"\x"`,
		"short unicode":       `"\u12"`,
		"signed unicode":      `"\u+123"`,
		"unterminated":        `"abc`,
		"unterminated array":  `[1`,
		"unterminated object": `{"a":1`,
		"unquoted key":        `{a:1}`,
		"bad literal":         `tru`,
		"too deep":            deep,
	}
	for name, in := range cases {
		_, err := Canonicalize([]byte(in))
		if !errors.Is(err, verify.ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}
}

func TestMarshal(t *testing.T) {
	type doc struct {
		Z string   `json:"z"`
		A float64  `json:"a"`
		M []string `json:"m"`
		T string   `json:"t"`
	}
	got, err := Marshal(doc{Z: "<&>", A: 1.0, M: []string{"é"}, T: "\u2028"})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":1,\"m\":[\"é\"],\"t\":\"\u2028\",\"z\":\"<&>\"}"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if _, err := Marshal(math.NaN()); err == nil {
		t.Fatal("NaN must fail")
	}
	if _, err := Marshal(int64(1) << 60); !errors.Is(err, verify.ErrMalformed) {
		t.Fatalf("big int: %v", err)
	}
	if _, err := Marshal(map[string]int64{"n": -(1 << 53)}); !errors.Is(err, verify.ErrMalformed) {
		t.Fatalf("big negative int: %v", err)
	}
	if got, err := Marshal(int64(1<<53 - 1)); err != nil || string(got) != "9007199254740991" {
		t.Fatalf("max safe int: %s %v", got, err)
	}
	if _, err := Marshal(make(chan int)); err == nil {
		t.Fatal("unsupported type must fail")
	}
}

func TestIdempotent(t *testing.T) {
	in := `{"b":[1.50,{"z":1,"y":"\u00e9"}],"a":1e2}`
	once, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	twice, err := Canonicalize(once)
	if err != nil || string(once) != string(twice) {
		t.Fatalf("not idempotent: %s vs %s (%v)", once, twice, err)
	}
}

func FuzzCanonicalize(f *testing.F) {
	for _, s := range []string{
		`{"a":1,"b":[true,null,"x"]}`, `[1e30,0.5,-0]`, `"\ud83d\ude00"`, `{"a":1,"a":2}`,
		"\"\xff\"", `{"\u0061":{"b":[]}}`, ``, `9007199254740993`, strings.Repeat("[", 300),
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := Canonicalize(in)
		if err != nil {
			if verify.Classify(err) != verify.Malformed {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		// Canonical output must itself canonicalize to itself.
		again, err := Canonicalize(out)
		if err != nil || string(again) != string(out) {
			t.Fatalf("not idempotent: %q -> %q (%v)", out, again, err)
		}
	})
}
