package subtitles

import (
	"bytes"
	"strings"
	"time"
	"unicode/utf8"
)

// Parse reads an uploaded WebVTT or SRT file (told apart by its first line) and returns the
// validated track. duration is the asset's duration: no cue may end more than [Tolerance] after it.
//
// The rules, all strict:
//   - at most [MaxBytes], valid UTF-8, no NUL; a leading byte order mark is removed; CRLF and CR
//     line endings are read as LF;
//   - every cue has a timing line, text that is not empty after sanitizing, and times that are not
//     negative, end after they start, and do not start before the cue before;
//   - cues may overlap (two speakers at once is ordinary);
//   - NOTE, STYLE and REGION blocks, cue identifiers and cue settings are dropped.
func Parse(data []byte, duration time.Duration) (*Track, error) {
	if len(data) > MaxBytes {
		return nil, problem("file", "the file is larger than %d bytes", MaxBytes)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, problem("file", "the file must be UTF-8 text")
	}
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	blocks := splitBlocks(text)
	if len(blocks) == 0 {
		return nil, problem("file", "the file is empty")
	}
	var (
		t   *Track
		err error
	)
	if isVTTHeader(blocks[0][0]) {
		t, err = parseVTT(blocks[1:])
	} else {
		t, err = parseSRT(blocks)
	}
	if err != nil {
		return nil, err
	}
	return finish(t, duration, "file")
}

// splitBlocks splits text into blocks of lines separated by blank lines. A line of only spaces or
// tabs is blank.
func splitBlocks(text string) [][]string {
	var blocks [][]string
	var cur []string
	for _, l := range strings.Split(text, "\n") {
		if strings.Trim(l, " \t") == "" {
			if len(cur) > 0 {
				blocks = append(blocks, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, l)
	}
	if len(cur) > 0 {
		blocks = append(blocks, cur)
	}
	return blocks
}

// isVTTHeader reports whether line is the WEBVTT signature: the word, alone or followed by a space
// or tab and any text.
func isVTTHeader(line string) bool {
	rest, ok := strings.CutPrefix(line, "WEBVTT")
	return ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t')
}

func parseVTT(blocks [][]string) (*Track, error) {
	t := &Track{}
	for i, b := range blocks {
		first := b[0]
		if !strings.Contains(first, "-->") {
			// A cue identifier, or a NOTE, STYLE or REGION block.
			if strings.HasPrefix(first, "NOTE") || strings.HasPrefix(first, "STYLE") || strings.HasPrefix(first, "REGION") {
				continue
			}
			b = b[1:]
			if len(b) == 0 || !strings.Contains(b[0], "-->") {
				return nil, problem("file", "block %d is not a cue", i+1)
			}
		}
		if len(t.Cues) >= MaxCues {
			return nil, problem("file", "the track has more than %d cues", MaxCues)
		}
		start, end, err := parseTiming(b[0], len(t.Cues)+1)
		if err != nil {
			return nil, err
		}
		text, err := sanitizeCueText(b[1:], len(t.Cues)+1)
		if err != nil {
			return nil, err
		}
		t.Cues = append(t.Cues, Cue{Start: start, End: end, Text: text})
	}
	return t, nil
}

func parseSRT(blocks [][]string) (*Track, error) {
	t := &Track{}
	for _, b := range blocks {
		// The cue number line is required by the format but carries nothing; a block that starts
		// with the timing line is accepted as well.
		if !strings.Contains(b[0], "-->") {
			b = b[1:]
		}
		if len(b) == 0 || !strings.Contains(b[0], "-->") {
			return nil, problem("file", "the file is neither WebVTT nor SRT")
		}
		if len(t.Cues) >= MaxCues {
			return nil, problem("file", "the track has more than %d cues", MaxCues)
		}
		start, end, err := parseTiming(b[0], len(t.Cues)+1)
		if err != nil {
			return nil, err
		}
		text, err := sanitizeCueText(b[1:], len(t.Cues)+1)
		if err != nil {
			return nil, err
		}
		t.Cues = append(t.Cues, Cue{Start: start, End: end, Text: text})
	}
	return t, nil
}

// parseTiming reads "start --> end" and drops whatever follows the end time (cue settings in
// WebVTT, coordinates in some SRT files).
func parseTiming(line string, n int) (start, end int64, err error) {
	left, right, _ := strings.Cut(line, "-->")
	rightFields := strings.Fields(right)
	if len(rightFields) == 0 {
		return 0, 0, problem("file", "cue %d has no end time", n)
	}
	if start, err = parseTimestamp(strings.TrimSpace(left), n); err != nil {
		return 0, 0, err
	}
	if end, err = parseTimestamp(rightFields[0], n); err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

// parseTimestamp reads [hh:]mm:ss.ttt, also with a comma before the milliseconds (SRT). The hours
// are at most two digits; minutes and seconds are below 60; there are exactly three digits of
// milliseconds. A sign is not accepted, so a time is never negative.
func parseTimestamp(s string, n int) (int64, error) {
	bad := problem("file", "cue %d has a malformed time", n)
	clock, frac, ok := cutLast(s, '.')
	if !ok {
		if clock, frac, ok = cutLast(s, ','); !ok {
			return 0, bad
		}
	}
	if len(frac) != 3 || !allDigits(frac) {
		return 0, bad
	}
	parts := strings.Split(clock, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, bad
	}
	var v [3]int64 // hours, minutes, seconds
	off := 3 - len(parts)
	for i, p := range parts {
		if len(p) != 2 || !allDigits(p) {
			return 0, bad
		}
		v[off+i] = int64(p[0]-'0')*10 + int64(p[1]-'0')
	}
	if v[1] > 59 || v[2] > 59 {
		return 0, bad
	}
	ms := int64(frac[0]-'0')*100 + int64(frac[1]-'0')*10 + int64(frac[2]-'0')
	return ((v[0]*60+v[1])*60+v[2])*1000 + ms, nil
}

func cutLast(s string, sep byte) (before, after string, ok bool) {
	i := strings.LastIndexByte(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// sanitizeCueText cleans the lines of one cue and returns them joined with "\n". It rejects a cue
// with more than [MaxCueLines] lines or [MaxCueTextRunes] characters (counted before sanitizing, so
// a markup-heavy cue cannot grow past the cap by being rewritten).
func sanitizeCueText(lines []string, n int) (string, error) {
	runes := 0
	for _, l := range lines {
		if runes += utf8.RuneCountInString(l); runes > MaxCueTextRunes {
			return "", problem("file", "cue %d has more than %d characters of text", n, MaxCueTextRunes)
		}
	}
	// The whole cue is sanitized at once, so a tag opened on one line can close on a later one.
	var out []string
	for _, l := range strings.Split(sanitizeMarkup(strings.Join(lines, "\n")), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	if len(out) > MaxCueLines {
		return "", problem("file", "cue %d has more than %d lines", n, MaxCueLines)
	}
	text := strings.Join(out, "\n")
	if !hasVisibleText(text) {
		return "", nil // check reports the cue as empty
	}
	return text, nil
}
