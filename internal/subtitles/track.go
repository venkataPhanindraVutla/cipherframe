// Package subtitles is subtitle tracks (M7-1, ADR 0043, ADR 0044): the strict WebVTT and SRT
// reader that turns an uploaded file or an imported transcript into one canonical WebVTT track,
// and the service that stores tracks, registers them and re-signs the asset's manifest.
//
// Nothing the uploader wrote survives except cue times and cue text, and the text only as plain
// text plus the WebVTT tags b, i, u, v, lang and c. The file name, the header text, cue
// identifiers, cue settings, notes, styles and regions are all dropped, and the output is written
// by [Track.WebVTT] from the parsed cues, never copied from the input.
package subtitles

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits (ADR 0043 sets the size and the track count; the rest are ADR 0044).
const (
	// MaxBytes is the largest track: the uploaded file and the WebVTT written from it.
	MaxBytes = 2 << 20
	// MaxRequestBytes bounds a request that carries a track (multipart framing or the JSON of a
	// transcript is larger than the track itself).
	MaxRequestBytes = 4 << 20
	// MaxTracks is the most tracks one asset has.
	MaxTracks = 20
	// MaxCues is the most cues in one track.
	MaxCues = 20000
	// MaxCueTextRunes and MaxCueLines cap one cue's text, after sanitizing.
	MaxCueTextRunes = 1000
	MaxCueLines     = 12
	// MaxLabelRunes caps the label; MaxSpeakerRunes the speaker of an imported cue.
	MaxLabelRunes   = 100
	MaxSpeakerRunes = 100
	// Tolerance is how far past the asset's duration a cue may end: encoders and subtitle tools
	// round differently.
	Tolerance = 2 * time.Second
)

// Problem is a rejected input. Its text never quotes the input, only says where and why.
type Problem struct {
	Field   string
	Message string
}

func (p *Problem) Error() string { return p.Field + ": " + p.Message }

func problem(field, format string, args ...any) *Problem {
	return &Problem{Field: field, Message: fmt.Sprintf(format, args...)}
}

// Cue is one cue. Times are milliseconds from the start of the media. Text is sanitized: plain
// text with the allowed tags, "&", "<" and ">" written as entities, lines separated by "\n".
type Cue struct {
	Start, End int64
	Text       string
}

// Track is a validated sequence of cues.
type Track struct {
	Cues []Cue
}

// check applies the rules that hold for every input format. cue is 1-based for messages.
func (t *Track) check(duration time.Duration, field string) error {
	if len(t.Cues) == 0 {
		return problem(field, "the track has no cues")
	}
	limit := (duration + Tolerance).Milliseconds()
	var prev int64
	for i, c := range t.Cues {
		n := i + 1
		switch {
		case c.Start < 0:
			return problem(field, "cue %d starts before zero", n)
		case c.End <= c.Start:
			return problem(field, "cue %d ends before it starts", n)
		case c.Start < prev:
			return problem(field, "cue %d starts before the cue before it", n)
		case c.End > limit:
			return problem(field, "cue %d ends after the end of the video", n)
		case c.Text == "":
			return problem(field, "cue %d has no text", n)
		}
		prev = c.Start
	}
	return nil
}

// WebVTT writes the canonical file: a bare header, then each cue with its times and text. It is
// deterministic, so the same cues always give the same bytes (and the same hash).
func (t *Track) WebVTT() []byte {
	var b strings.Builder
	b.WriteString("WEBVTT\n\n")
	for _, c := range t.Cues {
		b.WriteString(timestamp(c.Start))
		b.WriteString(" --> ")
		b.WriteString(timestamp(c.End))
		b.WriteByte('\n')
		b.WriteString(c.Text)
		b.WriteString("\n\n")
	}
	return []byte(b.String())
}

func timestamp(ms int64) string {
	return fmt.Sprintf("%02d:%02d:%02d.%03d", ms/3600000, ms/60000%60, ms/1000%60, ms%1000)
}

// finish checks the track and the size of what will be stored.
func finish(t *Track, duration time.Duration, field string) (*Track, error) {
	if len(t.Cues) > MaxCues {
		return nil, problem(field, "the track has more than %d cues", MaxCues)
	}
	if err := t.check(duration, field); err != nil {
		return nil, err
	}
	if len(t.WebVTT()) > MaxBytes {
		return nil, problem(field, "the track is larger than %d bytes once converted", MaxBytes)
	}
	return t, nil
}

// bcp47 is the shape of a well-formed language tag of the common kind: a 2 or 3 letter language,
// an optional 4 letter script, an optional region (2 letters or 3 digits) and variants. Extension
// and private-use subtags are not accepted: a player needs a language, not a locale database.
var bcp47 = regexp.MustCompile(`^([A-Za-z]{2,3})(?:-([A-Za-z]{4}))?(?:-([A-Za-z]{2}|[0-9]{3}))?((?:-(?:[A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3}))*)$`)

// NormalizeLanguage checks a BCP 47 tag and returns it in canonical case (en-US, zh-Hant-TW).
func NormalizeLanguage(s string) (string, error) {
	m := bcp47.FindStringSubmatch(s)
	if m == nil || len(s) > 35 {
		return "", problem("language", "must be a BCP 47 language tag such as en, pt-BR or zh-Hant")
	}
	var b strings.Builder
	b.WriteString(strings.ToLower(m[1]))
	if m[2] != "" {
		b.WriteString("-" + strings.ToUpper(m[2][:1]) + strings.ToLower(m[2][1:]))
	}
	if m[3] != "" {
		b.WriteString("-" + strings.ToUpper(m[3]))
	}
	b.WriteString(strings.ToLower(m[4]))
	return b.String(), nil
}

// CleanLabel trims a label and rejects one that is empty, too long or holds a control character
// (a label is shown to viewers by players, and written into a playlist).
func CleanLabel(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || utf8.RuneCountInString(s) > MaxLabelRunes || !utf8.ValidString(s):
		return "", problem("label", "must be 1 to %d characters", MaxLabelRunes)
	case strings.ContainsFunc(s, isUnsafeRune):
		return "", problem("label", "must not contain control or direction-override characters")
	}
	return s, nil
}

// isUnsafeRune reports a control character, a line or paragraph separator, a byte order mark or a
// bidirectional override or isolate: nothing a label or cue needs, and some can hide text.
func isUnsafeRune(r rune) bool {
	switch {
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return true
	case r == 0x2028 || r == 0x2029 || r == 0xfeff || r == 0xfffd:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
