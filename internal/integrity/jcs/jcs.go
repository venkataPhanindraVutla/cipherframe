// Package jcs implements the JSON Canonicalization Scheme, RFC 8785, for the I-JSON subset that
// Cipherframe signs.
//
// It is implemented here instead of importing a library because the scheme is small: a strict
// JSON parser, UTF-16 code unit ordering of member names, the fixed string escaping and the
// ECMAScript number serialisation (which Go's strconv already produces the digits for). Owning it
// lets the package enforce the I-JSON rules that RFC 8785 requires and general-purpose
// canonicalizers often skip, and keeps the verifier free of third-party code.
//
// Input is rejected (with an error wrapping verify.ErrMalformed) when it is not valid JSON, is
// not valid UTF-8, has a lone surrogate escape, repeats an object member name (after unescaping),
// nests deeper than [MaxDepth], or overflows a double. [Canonicalize] follows RFC 8785 for integer
// literals beyond 2^53-1 (they round to the nearest double, as ECMAScript does), which keeps it
// idempotent on its own output. [Marshal] is stricter: a Go integer that does not fit a double
// exactly is an error rather than a silent rounding of, say, a size; encode such values as strings
// (RFC 7493 section 2.2).
package jcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
)

// MaxDepth is the maximum nesting depth of arrays and objects.
const MaxDepth = 256

// maxSafeInteger is 2^53-1, the largest integer a double represents exactly and uniquely.
const maxSafeInteger = 1<<53 - 1

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: jcs: "+format, append([]any{verify.ErrMalformed}, args...)...)
}

// Marshal encodes v with encoding/json and returns its canonical form. Numbers pass through
// float64, so an integer beyond 2^53-1 is rejected rather than rounded. Go strings that are not valid UTF-8 are
// replaced with U+FFFD by encoding/json before this package sees them; use strings known to be
// valid.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jcs: marshal: %w", err)
	}
	return canonicalize(raw, true)
}

// Canonicalize returns the RFC 8785 canonical form of the JSON text in data.
func Canonicalize(data []byte) ([]byte, error) { return canonicalize(data, false) }

func canonicalize(data []byte, strictInts bool) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, malformed("input is not valid UTF-8")
	}
	p := &parser{data: data, strictInts: strictInts}
	out := make([]byte, 0, len(data))
	p.skipSpace()
	out, err := p.value(out, 0)
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.data) {
		return nil, malformed("trailing data at offset %d", p.pos)
	}
	return out, nil
}

type parser struct {
	data       []byte
	pos        int
	strictInts bool // reject integer literals beyond 2^53-1
}

func (p *parser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value(out []byte, depth int) ([]byte, error) {
	if p.pos >= len(p.data) {
		return nil, malformed("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(out, depth)
	case c == '[':
		return p.array(out, depth)
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return appendString(out, s), nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number(out)
	case c == 't':
		return p.literal(out, "true")
	case c == 'f':
		return p.literal(out, "false")
	case c == 'n':
		return p.literal(out, "null")
	default:
		return nil, malformed("unexpected byte %q at offset %d", c, p.pos)
	}
}

func (p *parser) literal(out []byte, lit string) ([]byte, error) {
	if !bytes.HasPrefix(p.data[p.pos:], []byte(lit)) {
		return nil, malformed("invalid literal at offset %d", p.pos)
	}
	p.pos += len(lit)
	return append(out, lit...), nil
}

func (p *parser) array(out []byte, depth int) ([]byte, error) {
	if depth >= MaxDepth {
		return nil, malformed("nesting deeper than %d", MaxDepth)
	}
	p.pos++ // [
	out = append(out, '[')
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return append(out, ']'), nil
	}
	for first := true; ; first = false {
		if !first {
			out = append(out, ',')
		}
		p.skipSpace()
		var err error
		if out, err = p.value(out, depth+1); err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil, malformed("unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return append(out, ']'), nil
		default:
			return nil, malformed("expected ',' or ']' at offset %d", p.pos)
		}
	}
}

type member struct {
	key   string
	units []uint16 // UTF-16 code units of key, the RFC 8785 sort key
	value []byte   // canonical value
}

func (p *parser) object(out []byte, depth int) ([]byte, error) {
	if depth >= MaxDepth {
		return nil, malformed("nesting deeper than %d", MaxDepth)
	}
	p.pos++ // {
	var members []member
	seen := map[string]struct{}{}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return append(out, '{', '}'), nil
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, malformed("expected member name at offset %d", p.pos)
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, dup := seen[key]; dup {
			return nil, malformed("duplicate member name %q", key)
		}
		seen[key] = struct{}{}
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, malformed("expected ':' at offset %d", p.pos)
		}
		p.pos++
		p.skipSpace()
		val, err := p.value(nil, depth+1)
		if err != nil {
			return nil, err
		}
		members = append(members, member{key: key, units: utf16.Encode([]rune(key)), value: val})
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil, malformed("unterminated object")
		}
		c := p.data[p.pos]
		p.pos++
		if c == '}' {
			break
		}
		if c != ',' {
			return nil, malformed("expected ',' or '}' at offset %d", p.pos-1)
		}
	}
	sort.Slice(members, func(i, j int) bool { return lessUnits(members[i].units, members[j].units) })
	out = append(out, '{')
	for i, m := range members {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendString(out, m.key)
		out = append(out, ':')
		out = append(out, m.value...)
	}
	return append(out, '}'), nil
}

func lessUnits(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// str parses a JSON string at p.pos (which is at the opening quote) and returns its value.
func (p *parser) str() (string, error) {
	p.pos++ // opening quote
	var sb strings.Builder
	for {
		if p.pos >= len(p.data) {
			return "", malformed("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c < 0x20:
			return "", malformed("unescaped control character in string at offset %d", p.pos)
		case c == '\\':
			if err := p.escape(&sb); err != nil {
				return "", err
			}
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			sb.WriteRune(r)
			p.pos += size
		}
	}
}

func (p *parser) hex4() (rune, error) {
	if p.pos+4 > len(p.data) {
		return 0, malformed("truncated \\u escape")
	}
	var v rune
	for _, c := range p.data[p.pos : p.pos+4] {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | rune(c-'A'+10)
		default:
			return 0, malformed("invalid \\u escape at offset %d", p.pos)
		}
	}
	p.pos += 4
	return v, nil
}

func (p *parser) escape(sb *strings.Builder) error {
	p.pos++ // backslash
	if p.pos >= len(p.data) {
		return malformed("truncated escape")
	}
	c := p.data[p.pos]
	p.pos++
	switch c {
	case '"', '\\', '/':
		sb.WriteByte(c)
	case 'b':
		sb.WriteByte('\b')
	case 'f':
		sb.WriteByte('\f')
	case 'n':
		sb.WriteByte('\n')
	case 'r':
		sb.WriteByte('\r')
	case 't':
		sb.WriteByte('\t')
	case 'u':
		r, err := p.hex4()
		if err != nil {
			return err
		}
		switch {
		case utf16.IsSurrogate(r) && r >= 0xDC00:
			return malformed("lone low surrogate escape")
		case utf16.IsSurrogate(r):
			if p.pos+2 > len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
				return malformed("lone high surrogate escape")
			}
			p.pos += 2
			lo, err := p.hex4()
			if err != nil {
				return err
			}
			if lo < 0xDC00 || lo > 0xDFFF {
				return malformed("high surrogate not followed by a low surrogate")
			}
			r = utf16.DecodeRune(r, lo)
		}
		sb.WriteRune(r)
	default:
		return malformed("invalid escape \\%c", c)
	}
	return nil
}

// appendString appends s as a JSON string using the RFC 8785 section 3.2.2.2 escaping: only
// backspace, tab, line feed, form feed, carriage return, quote and backslash have short escapes;
// other control characters use lower-case \u00xx; everything else is emitted literally.
func appendString(out []byte, s string) []byte {
	const hexdigits = "0123456789abcdef"
	out = append(out, '"')
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '"':
			out = append(out, '\\', '"')
		case c == '\\':
			out = append(out, '\\', '\\')
		case c == '\b':
			out = append(out, '\\', 'b')
		case c == '\t':
			out = append(out, '\\', 't')
		case c == '\n':
			out = append(out, '\\', 'n')
		case c == '\f':
			out = append(out, '\\', 'f')
		case c == '\r':
			out = append(out, '\\', 'r')
		case c < 0x20:
			out = append(out, '\\', 'u', '0', '0', hexdigits[c>>4], hexdigits[c&0xf])
		default:
			out = append(out, c)
		}
	}
	return append(out, '"')
}

func (p *parser) number(out []byte) ([]byte, error) {
	start := p.pos
	d := p.data
	i := p.pos
	if i < len(d) && d[i] == '-' {
		i++
	}
	digits := func() int {
		n := 0
		for i < len(d) && d[i] >= '0' && d[i] <= '9' {
			i++
			n++
		}
		return n
	}
	switch {
	case i < len(d) && d[i] == '0':
		i++
	case i < len(d) && d[i] >= '1' && d[i] <= '9':
		digits()
	default:
		return nil, malformed("invalid number at offset %d", start)
	}
	isInt := true
	if i < len(d) && d[i] == '.' {
		isInt = false
		i++
		if digits() == 0 {
			return nil, malformed("invalid number at offset %d", start)
		}
	}
	if i < len(d) && (d[i] == 'e' || d[i] == 'E') {
		isInt = false
		i++
		if i < len(d) && (d[i] == '+' || d[i] == '-') {
			i++
		}
		if digits() == 0 {
			return nil, malformed("invalid number at offset %d", start)
		}
	}
	text := string(d[start:i])
	p.pos = i
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return nil, malformed("number %q out of range", text)
	}
	if p.strictInts && isInt && math.Abs(f) > maxSafeInteger {
		return nil, malformed("integer %s exceeds 2^53-1; encode it as a string", text)
	}
	return append(out, FormatNumber(f)...), nil
}

// FormatNumber serialises f as ECMAScript Number::toString does (RFC 8785 section 3.2.2.3).
// f must be finite; negative zero is "0".
func FormatNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// Shortest round-trip digits: "d.ddde±XX".
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	k := len(digits)
	n := exp + 1 // value = 0.DIGITS * 10^n
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	expSign := "+"
	if n-1 < 0 {
		expSign = "-"
	}
	ea := n - 1
	if ea < 0 {
		ea = -ea
	}
	if k == 1 {
		return sign + digits + "e" + expSign + strconv.Itoa(ea)
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + expSign + strconv.Itoa(ea)
}
