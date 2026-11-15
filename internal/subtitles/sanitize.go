package subtitles

import (
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// maxTagDepth is how many tags a cue may have open at once; deeper opening tags are dropped.
const maxTagDepth = 8

// entities are the character references WebVTT defines for cue text. Any other "&" is written as
// "&amp;", so no other reference (numeric ones included) ever reaches a player.
var entities = []string{"&amp;", "&lt;", "&gt;", "&nbsp;", "&lrm;", "&rlm;"}

// sanitizeMarkup turns the text of a WebVTT cue into safe cue text: plain text, the tags b, i, u,
// v, lang and c, and the references in [entities]. Every other tag is dropped and its inner text
// kept. A "<" that does not open a tag and every ">" are written as references, closing tags that
// match nothing are dropped and tags still open at the end are closed, so the result is always
// well formed. Attributes, classes on b, i and u, and anything not listed below are dropped:
//
//	<c> and <c.class>  classes of letters, digits and "_" only
//	<v Name>           annotation: no < > & ", at most MaxSpeakerRunes characters, required
//	<lang en-US>       annotation: a language tag, required
//
// A character that cannot be shown (a control character, a line separator, a bidirectional
// override) is dropped, and a tab becomes a space.
func sanitizeMarkup(s string) string {
	var b strings.Builder
	var stack []string
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '<':
			if j := strings.IndexAny(s[i+1:], "<>"); j >= 0 && s[i+1+j] == '>' && startsTag(s[i+1:]) {
				b.WriteString(cleanTag(s[i+1:i+1+j], &stack))
				i += j + 2
				continue
			}
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		case r == '&':
			if e := entityAt(s[i:]); e != "" {
				b.WriteString(e)
				i += len(e)
				continue
			}
			b.WriteString("&amp;")
		case r == '\n':
			b.WriteByte('\n')
		case r == '\t':
			b.WriteByte(' ')
		case isUnsafeRune(r):
		default:
			b.WriteRune(r)
		}
		i += size
	}
	for i := len(stack) - 1; i >= 0; i-- {
		b.WriteString("</" + stack[i] + ">")
	}
	// A ">" is never written raw and annotations and classes cannot hold "--", so this cannot
	// happen; if it ever did, the cue would end early, so refuse to let it through.
	return strings.ReplaceAll(b.String(), "-->", "--&gt;")
}

// startsTag reports whether what follows a "<" can be a tag: a letter, a number (timestamp tags) or
// "/". A "<" followed by anything else, white space included, is just a less-than sign.
func startsTag(s string) bool {
	return s != "" && (s[0] == '/' || (s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= '0' && s[0] <= '9'))
}

// hasVisibleText reports whether sanitized cue text shows anything once its tags are removed.
func hasVisibleText(s string) bool {
	for {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i:], '>')
		if j < 0 {
			break
		}
		s = s[:i] + s[i+j+1:]
	}
	return strings.TrimSpace(strings.ReplaceAll(s, "&nbsp;", "")) != ""
}

func entityAt(s string) string {
	for _, e := range entities {
		if strings.HasPrefix(s, e) {
			return e
		}
	}
	return ""
}

// cleanTag returns what to write for the tag whose text between "<" and ">" is body, and keeps
// stack, the tags written and not yet closed, up to date. It returns "" for a tag to drop.
func cleanTag(body string, stack *[]string) string {
	closing := strings.HasPrefix(body, "/")
	body = strings.TrimPrefix(body, "/")
	head, annotation, _ := strings.Cut(strings.NewReplacer("\t", " ", "\n", " ").Replace(body), " ")
	name, classes, _ := strings.Cut(head, ".")
	switch name {
	case "b", "i", "u", "c", "v", "lang":
	default: // includes timestamp tags, ruby, and anything unknown
		return ""
	}
	if closing {
		if n := len(*stack); n > 0 && (*stack)[n-1] == name {
			*stack = (*stack)[:n-1]
			return "</" + name + ">"
		}
		return ""
	}
	if len(*stack) >= maxTagDepth {
		return ""
	}
	var out string
	switch name {
	case "b", "i", "u":
		out = "<" + name + ">"
	case "c":
		out = "<c" + cleanClasses(classes) + ">"
	case "v":
		a := annotationText(annotation, MaxSpeakerRunes)
		if a == "" {
			return ""
		}
		out = "<v " + a + ">"
	case "lang":
		tag, err := NormalizeLanguage(strings.TrimSpace(annotation))
		if err != nil {
			return ""
		}
		out = "<lang " + tag + ">"
	}
	*stack = append(*stack, name)
	return out
}

// cleanClasses keeps the classes (".a.b") that are made of letters, digits and "_", at most eight.
func cleanClasses(s string) string {
	var out strings.Builder
	n := 0
	for _, c := range strings.Split(s, ".") {
		if c == "" || len(c) > 32 || n == 8 {
			continue
		}
		ok := true
		for i := 0; i < len(c); i++ {
			ch := c[i]
			if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '_' {
				ok = false
			}
		}
		if ok {
			out.WriteString("." + c)
			n++
		}
	}
	return out.String()
}

// annotationText makes text safe for the annotation of a <v> tag: no markup characters, quotes,
// control characters or runs of white space, no "--", at most max characters.
func annotationText(s string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case r == ' ' || r == '\t':
			space = b.Len() > 0
			continue
		case r == '<' || r == '>' || r == '&' || r == '"' || isUnsafeRune(r):
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	out := b.String()
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if utf8.RuneCountInString(out) > max {
		out = string([]rune(out)[:max])
	}
	return strings.TrimSpace(out)
}

// plainText writes s as cue text with no markup at all: "&", "<" and ">" become references and
// unshowable characters are dropped. Line breaks are kept.
func plainText(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '&':
			b.WriteString("&amp;")
		case r == '<':
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		case r == '\t':
			b.WriteByte(' ')
		case r == '\n':
			b.WriteByte('\n')
		case isUnsafeRune(r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TranscriptCue is one cue of an imported transcript. Start and End are seconds from the start of
// the media. Speaker is optional.
type TranscriptCue struct {
	Start, End float64
	Text       string
	Speaker    string
}

// FromTranscript builds a track from imported timed text under the same rules as [Parse]. The text
// is plain text: it is never read as markup, so "<b>" in it is shown as typed. A speaker becomes
// a <v> tag around the cue.
func FromTranscript(cues []TranscriptCue, duration time.Duration) (*Track, error) {
	if len(cues) > MaxCues {
		return nil, problem("cues", "more than %d cues", MaxCues)
	}
	t := &Track{}
	for i, c := range cues {
		n := i + 1
		start, ok1 := millis(c.Start)
		end, ok2 := millis(c.End)
		if !ok1 || !ok2 {
			return nil, problem("cues", "cue %d has a time that is not between 0 and 100 hours", n)
		}
		if utf8.RuneCountInString(c.Text) > MaxCueTextRunes {
			return nil, problem("cues", "cue %d has more than %d characters of text", n, MaxCueTextRunes)
		}
		if !utf8.ValidString(c.Text) || !utf8.ValidString(c.Speaker) {
			return nil, problem("cues", "cue %d is not valid UTF-8", n)
		}
		var lines []string
		for _, l := range strings.Split(plainText(c.Text), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, l)
			}
		}
		if len(lines) > MaxCueLines {
			return nil, problem("cues", "cue %d has more than %d lines", n, MaxCueLines)
		}
		text := strings.Join(lines, "\n")
		if sp := annotationText(c.Speaker, MaxSpeakerRunes); sp != "" && text != "" {
			text = "<v " + sp + ">" + text + "</v>"
		}
		t.Cues = append(t.Cues, Cue{Start: start, End: end, Text: text})
	}
	return finish(t, duration, "cues")
}

// millis converts seconds to whole milliseconds, rounding. It refuses a value that is not a number
// or is outside 0 to 100 hours.
func millis(sec float64) (int64, bool) {
	if math.IsNaN(sec) || sec < 0 || sec > 360000 {
		return 0, false
	}
	return int64(math.Round(sec * 1000)), true
}
