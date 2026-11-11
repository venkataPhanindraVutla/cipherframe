package media

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// capabilityTimeout bounds each FFmpeg listing command.
const capabilityTimeout = 20 * time.Second

// maxListingOutput caps a listing such as -encoders.
const maxListingOutput = 1 << 20

// Tools are the FFmpeg and FFprobe binaries the worker runs, as configured (a path or a bare name
// found on PATH).
type Tools struct {
	FFmpeg  string
	FFprobe string
}

// requirement is one named feature a listing must contain. anyOf lists acceptable names; the
// first is the one the worker's own build provides.
type requirement struct {
	anyOf []string
}

func (r requirement) String() string {
	if len(r.anyOf) == 1 {
		return r.anyOf[0]
	}
	return strings.Join(r.anyOf, " or ")
}

func one(name string) requirement { return requirement{anyOf: []string{name}} }

// listing is an FFmpeg option that prints a table of features, and what the worker needs in it.
type listing struct {
	flag string
	kind string
	need []requirement
}

// capabilities is what the worker needs from an FFmpeg (ADR 0024): the decoders, demuxers,
// encoders, muxers, filters and protocols of the minimal build. The native "av1" decoder of FFmpeg
// is hardware-only, so software AV1 decoding needs libdav1d or libaom.
var capabilities = []listing{
	{flag: "-encoders", kind: "encoder", need: []requirement{one("libx264"), one("aac")}},
	{flag: "-decoders", kind: "decoder", need: []requirement{
		one("h264"), one("hevc"), one("vp8"), one("vp9"),
		{anyOf: []string{"libdav1d", "libaom-av1"}},
		one("aac"), one("opus"),
		{anyOf: []string{"mp3float", "mp3"}},
	}},
	{flag: "-muxers", kind: "muxer", need: []requirement{one("mp4"), one("hls")}},
	{flag: "-demuxers", kind: "demuxer", need: []requirement{one("mov"), one("matroska")}},
	{flag: "-protocols", kind: "protocol", need: []requirement{one("file"), one("pipe")}},
	{flag: "-filters", kind: "filter", need: []requirement{
		one("scale"), one("format"), one("aresample"), one("null"), one("anull"), one("setsar"), one("fps"), one("split"),
	}},
}

// CheckCapabilities verifies that the configured FFmpeg and FFprobe run and that FFmpeg provides
// the encoders, decoders, muxers, demuxers, protocols and filters the worker needs. The error lists
// everything that is missing in one message, so an operator fixes it in one go. The worker calls it
// at startup and refuses to start when it fails.
func (t Tools) CheckCapabilities(ctx context.Context) error {
	var problems []string

	if _, err := runBounded(ctx, t.FFprobe, "-hide_banner", "-version"); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		problems = append(problems, fmt.Sprintf("ffprobe %q does not run (%v)", t.FFprobe, err))
	}

	// -buildconf proves the binary is a real FFmpeg and prints its configuration for the log.
	if _, err := runBounded(ctx, t.FFmpeg, "-hide_banner", "-buildconf"); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("media: ffmpeg %q does not run (%w)%s", t.FFmpeg, err, joinProblems(problems))
	}

	for _, l := range capabilities {
		res, err := runBounded(ctx, t.FFmpeg, "-hide_banner", l.flag)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			problems = append(problems, fmt.Sprintf("ffmpeg %s failed (%v)", l.flag, err))
			continue
		}
		have := parseListing(res.stdout, l.flag)
		var missing []string
		for _, r := range l.need {
			found := false
			for _, n := range r.anyOf {
				if have[n] {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, r.String())
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			problems = append(problems, fmt.Sprintf("missing %s(s): %s", l.kind, strings.Join(missing, ", ")))
		}
	}
	if len(problems) > 0 {
		return errors.New("media: the configured FFmpeg cannot be used by the worker: " + strings.Join(problems, "; "))
	}
	return nil
}

func joinProblems(p []string) string {
	if len(p) == 0 {
		return ""
	}
	return "; " + strings.Join(p, "; ")
}

// runBounded runs a short listing command under capabilityTimeout.
func runBounded(ctx context.Context, bin string, args ...string) (runResult, error) {
	ctx, cancel := context.WithTimeout(ctx, capabilityTimeout)
	defer cancel()
	return run(ctx, bin, args, maxListingOutput)
}

// parseListing extracts feature names from an FFmpeg listing. Each table line is " FLAGS name  description"
// (for -protocols, the names come as a plain "Input:"/"Output:" list, one name per line).
func parseListing(out []byte, flag string) map[string]bool {
	names := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		switch flag {
		case "-protocols":
			if len(fields) == 1 && !strings.HasSuffix(fields[0], ":") {
				names[fields[0]] = true
			}
		case "-muxers", "-demuxers":
			// " E  mp4   MP4" / " D  matroska,webm   Matroska": names may be comma lists in -demuxers.
			if len(fields) >= 2 && isFlagColumn(fields[0]) {
				for _, n := range strings.Split(fields[1], ",") {
					names[n] = true
				}
			}
		default:
			// Encoders and decoders have a flags column like "V....D"; filters like "T.." followed
			// by the name.
			if len(fields) >= 2 && isFlagColumn(fields[0]) {
				if fields[1] != "=" {
					names[fields[1]] = true
				}
			}
		}
	}
	return names
}

// isFlagColumn reports whether s looks like the leading capability flags of a listing line (letters
// and dots, for example "V....D", "DE", "T.."). Header and separator lines do not match.
func isFlagColumn(s string) bool {
	if s == "" || len(s) > 8 {
		return false
	}
	for _, r := range s {
		if r != '.' && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}
