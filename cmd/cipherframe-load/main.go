// Command cipherframe-load is the load generator behind docs/load-tests.md (ADR 0061). Its play mode
// ramps virtual viewers that behave like the reference player; its transcode mode measures how fast
// the worker turns uploads into ready assets. It is a development tool and is not part of a release.
//
// It writes only counts and latencies: never a token, a session ID, a key or a URL.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/apiclient"
)

const usage = `cipherframe-load: load generator for a Cipherframe deployment

  cipherframe-load play      --asset ID --delivery proxy|presigned [--start 10 --step 10 --max 200 --step-duration 60s] [flags]
  cipherframe-load transcode --file clip.mp4 --media-seconds 60 [--jobs 4 --concurrency 1] [flags]

Common flags: --api URL (or $CIPHERFRAME_SERVER), --api-key-file FILE (or $CIPHERFRAME_API_KEY; never a flag
value), --raw FILE (per-request CSV), --summary FILE (summary CSV). Run a mode with -h for all flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "play":
		err = runPlay(ctx, os.Args[2:])
	case "transcode":
		err = runTranscode(ctx, os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cipherframe-load:", err)
		os.Exit(1)
	}
}

// common holds what both modes need: the API client and the output files.
type common struct {
	api, keyFile, rawPath, summaryPath string
	rawSample                          int
	key                                string
	client                             *apiclient.HTTPClient
	hc                                 *http.Client
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.api, "api", "", "api base URL (default $CIPHERFRAME_SERVER)")
	fs.StringVar(&c.keyFile, "api-key-file", "", "file holding the API key (default $CIPHERFRAME_API_KEY)")
	fs.StringVar(&c.rawPath, "raw", "", "write one CSV row per request (failures, and 1 in --raw-sample successes) to this file")
	fs.IntVar(&c.rawSample, "raw-sample", 1, "keep one successful request in this many in the raw file")
	fs.StringVar(&c.summaryPath, "summary", "", "write the per-step summary CSV to this file")
}

// setup resolves the key and builds the client. The transport is sized for many concurrent viewers.
func (c *common) setup() error {
	if c.api == "" {
		c.api = os.Getenv("CIPHERFRAME_SERVER")
	}
	c.api = strings.TrimRight(c.api, "/")
	if !strings.HasPrefix(c.api, "http://") && !strings.HasPrefix(c.api, "https://") {
		return errors.New("give the api base URL with --api or CIPHERFRAME_SERVER")
	}
	c.key = strings.TrimSpace(os.Getenv("CIPHERFRAME_API_KEY"))
	if c.keyFile != "" {
		b, err := os.ReadFile(c.keyFile)
		if err != nil {
			return errors.New("cannot read --api-key-file")
		}
		c.key = strings.TrimSpace(string(b))
	}
	if c.key == "" {
		return errors.New("give the API key in CIPHERFRAME_API_KEY or a file named by --api-key-file")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns, tr.MaxIdleConnsPerHost, tr.MaxConnsPerHost = 4096, 4096, 0
	c.hc = &http.Client{Transport: tr, Timeout: 60 * time.Second}
	var err error
	c.client, err = apiclient.NewClient(c.api, apiclient.WithHTTPClient(c.hc),
		apiclient.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
			r.Header.Set("Authorization", "Bearer "+c.key)
			return nil
		}))
	return err
}

// decode reads a JSON answer into out, or returns an error naming only the status and the
// problem code (a problem body carries no secret, but it is not echoed).
func decode(resp *http.Response, err error, out any) error {
	if err != nil {
		return errors.New("api request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		var p struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(b, &p)
		return fmt.Errorf("api answered %d %s", resp.StatusCode, p.Code)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return errors.New("api answer is not the expected JSON")
	}
	return nil
}
