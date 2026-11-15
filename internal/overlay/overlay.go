// Package overlay is the overlay watermark policy (ADR 0043, 0048): template validation, the
// session code, and the reference implementation of the drift path.
//
// The overlay is drawn by the player over the video. It is never burned in, it carries no viewer
// data, and it is deterrence only: whoever controls the player can remove it.
package overlay

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// Bounds of the settings.
const (
	MaxTemplateChars = 120
	MinOpacity       = 0.05
	MaxOpacity       = 0.8
	MinFontSize      = 0.015
	MaxFontSize      = 0.1
)

// The placeholders a template may use. The player substitutes {date} (the viewer's current UTC
// date as YYYY-MM-DD) and {time} (the UTC time as HH:MM:SS); the server substitutes the code.
const (
	PlaceholderCode = "{session_code}"
	PlaceholderDate = "{date}"
	PlaceholderTime = "{time}"
)

var placeholders = []string{PlaceholderCode, PlaceholderDate, PlaceholderTime}

// ValidateTemplate checks a template: 1 to 120 characters of valid UTF-8, no control, format,
// separator or private-use characters (so no line breaks), none of < > & (no markup), at least one
// placeholder, and no brace that is not part of one of the three placeholders.
func ValidateTemplate(t string) error {
	if !utf8.ValidString(t) {
		return errors.New("must be valid UTF-8")
	}
	if n := utf8.RuneCountInString(t); n < 1 || n > MaxTemplateChars {
		return errors.New("must be 1 to 120 characters")
	}
	for _, r := range t {
		switch {
		case r == unicode.ReplacementChar || unicode.In(r, unicode.C, unicode.Zl, unicode.Zp):
			return errors.New("must be plain text without control characters or line breaks")
		case r == '<' || r == '>' || r == '&':
			return errors.New("must not contain markup characters (< > &)")
		}
	}
	rest := t
	found := false
	for _, p := range placeholders {
		if strings.Contains(rest, p) {
			found = true
			rest = strings.ReplaceAll(rest, p, "")
		}
	}
	if strings.ContainsAny(rest, "{}") {
		return errors.New("may only use the placeholders {session_code}, {date} and {time}")
	}
	if !found {
		return errors.New("must contain at least one of {session_code}, {date} and {time}")
	}
	return nil
}

// ValidateSettings returns one field error per invalid setting.
func ValidateSettings(s db.OverlaySettings) []errs.FieldError {
	var out []errs.FieldError
	if err := ValidateTemplate(s.Template); err != nil {
		out = append(out, errs.FieldError{Field: "template", Message: err.Error()})
	}
	if !(s.Opacity >= MinOpacity && s.Opacity <= MaxOpacity) {
		out = append(out, errs.FieldError{Field: "opacity", Message: "must be between 0.05 and 0.8"})
	}
	if !(s.FontSizeFraction >= MinFontSize && s.FontSizeFraction <= MaxFontSize) {
		out = append(out, errs.FieldError{Field: "font_size_fraction", Message: "must be between 0.015 and 0.1"})
	}
	if len(s.Color) != 7 || s.Color[0] != '#' || strings.Trim(s.Color[1:], "0123456789ABCDEF") != "" {
		out = append(out, errs.FieldError{Field: "color", Message: "must be #RRGGBB in upper-case hexadecimal"})
	}
	return out
}

// codeAlphabet is base32 without the look-alikes 0, 1, I and O.
const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// CodeLen is the length of a session code: 40 bits.
const CodeLen = 8

// SessionCode is the code the player shows: the first 40 bits of
// SHA-256("cipherframe/overlay/code/v1" 0x00 || session hash || tenant UUID bytes), five bits per
// character of codeAlphabet. The session hash is db.SessionHash. It is one way and unrelated to the
// session ID, the token and the access trail's fingerprint (ADR 0048).
func SessionCode(sessionHash []byte, tenant id.TenantID) string {
	h := sha256.New()
	h.Write([]byte("cipherframe/overlay/code/v1\x00"))
	h.Write(sessionHash)
	u := tenant.UUID()
	h.Write(u[:])
	sum := h.Sum(nil)
	var bits uint64
	for _, b := range sum[:5] {
		bits = bits<<8 | uint64(b)
	}
	var out [CodeLen]byte
	for i := range out {
		out[i] = codeAlphabet[(bits>>(35-5*uint(i)))&31]
	}
	return string(out[:])
}

// ValidCode reports whether s has the shape of a session code.
func ValidCode(s string) bool {
	return len(s) == CodeLen && strings.Trim(s, codeAlphabet) == ""
}

// Drift constants, part of the algorithm "lissajous-v1" (spec/test-vectors/overlay/README.md).
const (
	Algorithm     = "lissajous-v1"
	PeriodSeconds = 240
	Margin        = 0.02
)

// freqPairs are the (kx, ky) frequencies, in cycles per period, the seed chooses from.
var freqPairs = [6][2]int{{1, 2}, {2, 1}, {1, 3}, {3, 1}, {2, 3}, {3, 2}}

// Seed is the drift seed of a session: the first 8 bytes of
// SHA-256("cipherframe/overlay/seed/v1" 0x00 || session ID text), lower-case hex (16 characters).
// It is one way: it reveals nothing usable about the session ID.
func Seed(sid id.SessionID) string {
	sum := sha256.Sum256([]byte("cipherframe/overlay/seed/v1\x00" + sid.String()))
	return hex.EncodeToString(sum[:8])
}

// Path is the parameters of one session's drift, derived from its seed.
type Path struct {
	KX, KY         int
	PhaseX, PhaseY float64 // radians, in [0, 2*pi)
}

// ParsePath derives the path from a seed of 16 hexadecimal characters: byte 0 modulo 6 picks the
// frequency pair, bytes 1-2 (big endian) the x phase and bytes 3-4 the y phase, each as a
// fraction of 2*pi over 65536. Bytes 5-7 are reserved.
func ParsePath(seed string) (Path, error) {
	b, err := hex.DecodeString(seed)
	if err != nil || len(b) != 8 {
		return Path{}, errors.New("overlay: the seed must be 16 hexadecimal characters")
	}
	f := freqPairs[int(b[0])%len(freqPairs)]
	return Path{
		KX: f[0], KY: f[1],
		PhaseX: 2 * math.Pi * float64(binary.BigEndian.Uint16(b[1:3])) / 65536,
		PhaseY: 2 * math.Pi * float64(binary.BigEndian.Uint16(b[3:5])) / 65536,
	}, nil
}

// At returns the position at t seconds since the player received the session response, as
// fractions in [0, 1] of the room the text has to move in: u = 0.5 + 0.5 sin(2 pi kx t / 240 + px)
// and v likewise with ky and py. The curve is closed with period 240 s and its speed never
// exceeds pi * 3 / 240, about 0.039 of the room per second.
func (p Path) At(t float64) (u, v float64) {
	w := 2 * math.Pi * t / PeriodSeconds
	return 0.5 + 0.5*math.Sin(float64(p.KX)*w+p.PhaseX), 0.5 + 0.5*math.Sin(float64(p.KY)*w+p.PhaseY)
}

// Place maps a position fraction to the offset of the text box's left (or top) edge, as a fraction
// of the frame width (or height): Margin + u * (1 - box - 2*Margin), where box is the text's
// width (or height) as a fraction of the frame. A box wider than the room sits at the margin.
func Place(u, box float64) float64 {
	return Margin + u*math.Max(0, 1-box-2*Margin)
}
