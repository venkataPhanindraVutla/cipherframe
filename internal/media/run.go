// Package media is Cipherframe's media toolkit (ADR 0024): it runs FFprobe and FFmpeg as separate
// processes (invariant I1), checks that the configured binaries can do what the worker needs,
// probes and validates untrusted sources, and picks the rendition ladder.
//
// FFmpeg and FFprobe are only ever started with exec.CommandContext and an argument array. They are
// never started through a shell and never linked as libraries. A source path is handed to them as
// an absolute path with a "file:" prefix and with every protocol except file and pipe disabled, so
// a hostile file name can be neither an option nor a URL.
package media

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// waitDelay is how long a killed process gets to release its pipes before Wait gives up on them.
const waitDelay = 5 * time.Second

// errOutputTooLarge is returned when a tool writes more than the caller allowed.
var errOutputTooLarge = errors.New("media: tool output exceeds the size limit")

// cappedBuffer collects at most limit bytes and fails the write when more arrives, which makes the
// process's pipe fail so it stops instead of filling memory.
type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.limit {
		c.overflow = true
		return 0, errOutputTooLarge
	}
	return c.buf.Write(p)
}

// runResult is what a finished tool left behind.
type runResult struct {
	stdout   []byte
	stderr   string // truncated; for logs, never for clients
	exitCode int
}

// run starts bin with args, reads at most maxOut bytes of stdout and a short tail of stderr, and
// stops the process when ctx ends. The child gets an empty environment, so none of the worker's
// secrets reach FFmpeg. It never uses a shell.
func run(ctx context.Context, bin string, args []string, maxOut int) (runResult, error) {
	if strings.TrimSpace(bin) == "" {
		return runResult{}, errors.New("media: no binary configured")
	}
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // I1: argument array, never a shell; the binary is operator configuration
	cmd.Env = []string{"LC_ALL=C"}
	cmd.WaitDelay = waitDelay
	out := &cappedBuffer{limit: maxOut}
	errBuf := &cappedBuffer{limit: 16 << 10}
	cmd.Stdout = out
	cmd.Stderr = tolerantWriter{errBuf}

	err := cmd.Run()
	res := runResult{stdout: out.buf.Bytes(), stderr: strings.TrimSpace(errBuf.buf.String())}
	if cerr := ctx.Err(); cerr != nil {
		return res, cerr
	}
	if out.overflow {
		return res, errOutputTooLarge
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.exitCode = ee.ExitCode()
		return res, fmt.Errorf("%s exited with code %d: %s", filepath.Base(bin), res.exitCode, res.stderr)
	default:
		return res, fmt.Errorf("media: run %s: %w", filepath.Base(bin), err)
	}
	return res, nil
}

// tolerantWriter swallows overflow instead of failing, so a chatty stderr is truncated rather than
// killing the process.
type tolerantWriter struct{ w *cappedBuffer }

func (t tolerantWriter) Write(p []byte) (int, error) {
	room := t.w.limit - t.w.buf.Len()
	if room > 0 {
		if len(p) < room {
			room = len(p)
		}
		t.w.buf.Write(p[:room])
	}
	return len(p), nil
}

var _ io.Writer = tolerantWriter{}

// SourceURL turns a local source path into the argument FFmpeg and FFprobe receive. The path must be
// absolute; it is cleaned and given a "file:" prefix, so it cannot be read as an option (a name
// starting with "-") or as a URL (a name such as "http://...").
func SourceURL(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("media: source path must be absolute")
	}
	if strings.ContainsRune(path, 0) {
		return "", errors.New("media: source path contains a NUL byte")
	}
	return "file:" + filepath.Clean(path), nil
}
