package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/apiclient"
)

// Exit codes of the commands that talk to the server (ADR 0051). verify keeps 0 to 3 (see
// verify.go); exitUsage is shared.
const (
	exitAPI         = 4 // the server refused: unauthenticated, forbidden, invalid request, other 4xx or 5xx
	exitNotFound    = 5 // 404
	exitConflict    = 6 // 409 (conflict, quota_exceeded) and 429 (rate_limited)
	exitUnavailable = 7 // no answer: network error, timeout, 502 to 504
	exitIncomplete  = 8 // --wait ended without success: the asset failed, or the wait timed out
)

const (
	maxBodyBytes   = 16 << 20
	defaultTimeout = 30 * time.Second
)

// Poll timing for --wait; variables so tests can shorten them.
var (
	pollMin = time.Second
	pollMax = 10 * time.Second
)

// cliError carries an exit code and the text to show for a failure.
type cliError struct {
	code    int
	kind    string // short stable word for --json: usage, network, incomplete or the problem code
	msg     string
	problem *apiclient.Problem
}

func (e *cliError) Error() string { return e.msg }

func usageErr(format string, a ...any) error {
	return &cliError{code: exitUsage, kind: "usage", msg: fmt.Sprintf(format, a...)}
}

// cli is the state of one command run.
type cli struct {
	stdout, stderr io.Writer
	server, key    string
	json           bool
	idOnly         bool // print the bare asset ID instead of "ID  state" (upload)
	timeout        time.Duration
	hc             *http.Client // no overall timeout: each request gets its own context deadline
	secrets        []string     // values to scrub from anything printed
	api            *apiclient.HTTPClient
}

// commonFlags are the flags every server command takes.
type commonFlags struct {
	server, keyFile string
	json            bool
	timeout         time.Duration
}

func (f *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.server, "server", "", "api base URL (default $CIPHERFRAME_SERVER)")
	fs.StringVar(&f.keyFile, "api-key-file", "", "file holding the API key (default $CIPHERFRAME_API_KEY)")
	fs.BoolVar(&f.json, "json", false, "machine-readable output on stdout")
	fs.DurationVar(&f.timeout, "timeout", defaultTimeout, "timeout of each request")
}

// newCLI resolves the server URL and the API key and builds the typed client.
func newCLI(f commonFlags, stdout, stderr io.Writer) (*cli, error) {
	c := &cli{stdout: stdout, stderr: stderr, json: f.json, timeout: f.timeout, hc: &http.Client{}}
	if c.timeout <= 0 {
		return nil, usageErr("--timeout must be positive")
	}
	c.server = f.server
	if c.server == "" {
		c.server = os.Getenv("CIPHERFRAME_SERVER")
	}
	u, err := url.Parse(c.server)
	if err != nil || c.server == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, usageErr("give the api base URL with --server or CIPHERFRAME_SERVER (http or https, no credentials)")
	}
	switch {
	case f.keyFile != "":
		b, err := os.ReadFile(f.keyFile)
		if err != nil {
			return nil, usageErr("read --api-key-file: %v", err)
		}
		c.key = strings.TrimSpace(string(b))
	default:
		c.key = strings.TrimSpace(os.Getenv("CIPHERFRAME_API_KEY"))
	}
	if c.key == "" {
		return nil, usageErr("give the API key in CIPHERFRAME_API_KEY or a file named by --api-key-file")
	}
	c.secrets = []string{c.key}
	c.api, err = apiclient.NewClient(strings.TrimRight(c.server, "/"),
		apiclient.WithHTTPClient(c.hc),
		apiclient.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
			r.Header.Set("Authorization", "Bearer "+c.key)
			return nil
		}))
	return c, err
}

// scrub removes known secrets from s.
func (c *cli) scrub(s string) string {
	for _, v := range c.secrets {
		if v != "" {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
	}
	return s
}

// ctx returns a context for one request.
func (c *cli) ctx(parent context.Context, mult int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, c.timeout*time.Duration(mult))
}

// netErr turns a transport error into a cliError that cannot carry a secret.
func (c *cli) netErr(err error) error {
	var ue *url.Error
	msg := err.Error()
	if errors.As(err, &ue) {
		msg = ue.Op + ": " + ue.Err.Error() // leaves the URL out
	}
	return &cliError{code: exitUnavailable, kind: "network", msg: c.scrub("cannot reach the server: " + msg)}
}

// finish reads a response. A 2xx body is decoded into out (when non-nil) and returned raw; any other
// status becomes a cliError carrying the problem.
func (c *cli) finish(resp *http.Response, err error, out any) ([]byte, error) {
	if err != nil {
		return nil, c.netErr(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, c.netErr(err)
	}
	if len(body) > maxBodyBytes {
		return nil, &cliError{code: exitAPI, kind: "response_too_large", msg: "the response is too large"}
	}
	if resp.StatusCode/100 != 2 {
		return nil, c.problemErr(resp.StatusCode, body)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return nil, &cliError{code: exitAPI, kind: "bad_response", msg: "the server's answer is not the expected JSON"}
		}
	}
	return body, nil
}

// problemErr builds the error for a non-2xx answer: an RFC 9457 problem when the body is one.
func (c *cli) problemErr(status int, body []byte) error {
	e := &cliError{code: exitCodeFor(status), kind: "http_" + fmt.Sprint(status)}
	var p apiclient.Problem
	if json.Unmarshal(body, &p) == nil && p.Code != "" {
		e.problem, e.kind = &p, string(p.Code)
		e.msg = fmt.Sprintf("%s: %s (code %s, request id %s)", p.Title, p.Detail, p.Code, p.RequestId)
		if p.Limit != nil {
			e.msg += ", limit " + *p.Limit
		}
	} else {
		e.msg = fmt.Sprintf("the server answered HTTP %d", status)
	}
	e.msg = c.scrub(e.msg)
	return e
}

func exitCodeFor(status int) int {
	switch status {
	case http.StatusNotFound:
		return exitNotFound
	case http.StatusConflict, http.StatusTooManyRequests:
		return exitConflict
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusRequestTimeout:
		return exitUnavailable
	}
	return exitAPI
}

// report prints err on stderr (as JSON with --json) and returns its exit code.
func report(stderr io.Writer, name string, asJSON bool, c *cli, err error) int {
	ce := &cliError{}
	if !errors.As(err, &ce) {
		ce = &cliError{code: exitAPI, kind: "error", msg: err.Error()}
	}
	msg := ce.msg
	if c != nil {
		msg = c.scrub(msg)
	}
	if asJSON {
		doc := map[string]any{"code": ce.kind, "detail": msg, "exit_code": ce.code}
		if p := ce.problem; p != nil {
			doc["status"], doc["request_id"], doc["retryable"] = p.Status, p.RequestId, p.Retryable
			if p.Limit != nil {
				doc["limit"] = *p.Limit
			}
		}
		_ = json.NewEncoder(stderr).Encode(map[string]any{"error": doc})
	} else {
		_, _ = fmt.Fprintf(stderr, "cipherframe %s: %s\n", name, msg)
	}
	return ce.code
}

// command is one server subcommand.
type command struct {
	name, synopsis, help string
	setup                func(fs *flag.FlagSet) func(c *cli, args []string) error
}

// run parses args (flags may follow the positional arguments), builds the cli and runs the command.
func (cmd command) run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var cf commonFlags
	cf.register(fs)
	do := cmd.setup(fs)
	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprint(stdout, cmd.helpText(fs))
		return 0
	}
	if err != nil {
		return report(stderr, cmd.name, cf.json, nil, usageErr("%v (see cipherframe help %s)", err, cmd.name))
	}
	c, err := newCLI(cf, stdout, stderr)
	if err != nil {
		return report(stderr, cmd.name, cf.json, nil, err)
	}
	if err := do(c, pos); err != nil {
		return report(stderr, cmd.name, c.json, c, err)
	}
	return 0
}

func (cmd command) helpText(fs *flag.FlagSet) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: cipherframe %s\n\n%s\n\nFlags:\n", cmd.synopsis, strings.TrimSpace(cmd.help))
	fs.SetOutput(&b)
	fs.PrintDefaults()
	fs.SetOutput(io.Discard)
	b.WriteString("\n" + exitCodeHelp)
	return b.String()
}

// parseInterspersed parses flags that may come before, between and after positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// onePositional checks for exactly one positional argument.
func onePositional(pos []string, what string) (string, error) {
	if len(pos) != 1 {
		return "", usageErr("expected exactly one %s", what)
	}
	return pos[0], nil
}

// printJSON writes raw JSON with a trailing newline.
func (c *cli) printJSON(raw []byte) {
	_, _ = c.stdout.Write(append(raw[:len(raw):len(raw)], '\n'))
}

func (c *cli) diag(format string, a ...any) {
	_, _ = fmt.Fprintf(c.stderr, format+"\n", a...)
}

const exitCodeHelp = `Exit codes: 0 ok, 3 usage error, 4 the server refused the request, 5 not found,
6 conflict or quota (409, 429), 7 network error, timeout or server unavailable,
8 --wait ended without success (asset failed or wait timed out).
verify keeps its own codes: 0 all ours, 1 any modified, 2 cannot say, 3 usage error.
`
