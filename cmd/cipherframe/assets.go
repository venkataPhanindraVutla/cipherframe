package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/apiclient"
)

var assetCommands = []command{
	{
		name: "status", synopsis: "status ASSET_ID [flags]",
		help: "Print the state of one asset (and its failure code when it failed).",
		setup: func(*flag.FlagSet) func(*cli, []string) error {
			return func(c *cli, pos []string) error {
				id, err := onePositional(pos, "asset ID")
				if err != nil {
					return err
				}
				a, _, err := c.getAsset(context.Background(), id)
				if err != nil {
					return err
				}
				if c.json {
					raw, _ := json.Marshal(struct {
						ID          string  `json:"id"`
						State       string  `json:"state"`
						FailureCode *string `json:"failure_code,omitempty"`
						UpdatedAt   string  `json:"updated_at"`
					}{a.Id, string(a.State), a.FailureCode, a.UpdatedAt.UTC().Format(time.RFC3339Nano)})
					c.printJSON(raw)
					return nil
				}
				c.printf("%s  %s", a.Id, a.State)
				if a.FailureCode != nil {
					c.printf("  (%s)", *a.FailureCode)
				}
				c.printf("\n")
				return nil
			}
		},
	},
	{
		name: "inspect", synopsis: "inspect ASSET_ID [flags]",
		help: "Print the full asset document as JSON (always JSON, indented without --json).",
		setup: func(*flag.FlagSet) func(*cli, []string) error {
			return func(c *cli, pos []string) error {
				id, err := onePositional(pos, "asset ID")
				if err != nil {
					return err
				}
				_, raw, err := c.getAsset(context.Background(), id)
				if err != nil {
					return err
				}
				if !c.json {
					raw = indentJSON(raw)
				}
				c.printJSON(raw)
				return nil
			}
		},
	},
	{
		name: "list", synopsis: "list [--limit N] [--cursor C] [flags]",
		help: "List the tenant's assets, oldest first, one page at a time. When more remain the next\n" +
			"cursor is printed (stderr, or next_cursor in the --json document).",
		setup: func(fs *flag.FlagSet) func(*cli, []string) error {
			limit := fs.Int("limit", 0, "page size, 1 to 100 (default: the server's, 50)")
			cursor := fs.String("cursor", "", "the next_cursor of the previous page")
			return func(c *cli, pos []string) error {
				if len(pos) != 0 {
					return usageErr("list takes no arguments")
				}
				p := &apiclient.ListAssetsParams{}
				if *limit != 0 {
					p.Limit = limit
				}
				if *cursor != "" {
					p.Cursor = cursor
				}
				ctx, cancel := c.ctx(context.Background(), 1)
				defer cancel()
				resp, err := c.api.ListAssets(ctx, p)
				var out apiclient.AssetList
				raw, err := c.finish(resp, err, &out)
				if err != nil {
					return err
				}
				if c.json {
					c.printJSON(raw)
					return nil
				}
				for _, a := range out.Items {
					c.printf("%s  %-10s %12d  %s\n", a.Id, a.State, a.SizeBytes, a.CreatedAt.Format(time.RFC3339))
				}
				if out.NextCursor != nil {
					c.diag("more: --cursor %s", *out.NextCursor)
				}
				return nil
			}
		},
	},
	{
		name: "process", synopsis: "process ASSET_ID [--wait] [flags]",
		help: "Commit an uploaded asset, which queues processing. Upload already does this; use process\n" +
			"to retry a commit that failed (for example on a storage quota) after making room. There is\n" +
			"no separate processing trigger in the API, so this is the commit call (ADR 0051).",
		setup: func(fs *flag.FlagSet) func(*cli, []string) error {
			w := addWaitFlags(fs)
			return func(c *cli, pos []string) error {
				id, err := onePositional(pos, "asset ID")
				if err != nil {
					return err
				}
				ctx, cancel := c.ctx(context.Background(), 1)
				resp, err := c.api.CommitAsset(ctx, id)
				var a apiclient.Asset
				raw, err := c.finish(resp, err, &a)
				cancel()
				if err != nil {
					return err
				}
				return c.finishAsset(a, raw, w)
			}
		},
	},
	{
		name: "delete", synopsis: "delete ASSET_ID [--wait] [flags]",
		help: "Start the verified deletion of an asset. With --wait, poll until the asset is deleted, then\n" +
			"print the signed deletion record (a DSSE envelope, JSON) on stdout, ready for\n" +
			"cipherframe verify --deletion-record. Without --wait the asset document is printed.",
		setup: func(fs *flag.FlagSet) func(*cli, []string) error {
			w := addWaitFlags(fs)
			return func(c *cli, pos []string) error {
				id, err := onePositional(pos, "asset ID")
				if err != nil {
					return err
				}
				ctx, cancel := c.ctx(context.Background(), 1)
				resp, err := c.api.DeleteAsset(ctx, id)
				var a apiclient.Asset
				raw, err := c.finish(resp, err, &a)
				cancel()
				if err != nil {
					return err
				}
				if !w.wait {
					return c.printAsset(a, raw)
				}
				c.diag("%s is %s; waiting for the deletion to finish", a.Id, a.State)
				if _, err := c.waitFor(context.Background(), id, w, func(a apiclient.Asset) (bool, error) {
					return a.State == apiclient.AssetStateDeleted, nil
				}); err != nil {
					return err
				}
				return c.printDeletionRecord(id)
			}
		},
	},
	{
		name: "deletion-record", synopsis: "deletion-record ASSET_ID [flags]",
		help: "Print the signed deletion record of a deleted asset (a DSSE envelope, JSON). Save it and check\n" +
			"it with cipherframe verify --deletion-record. An asset that is not deleted yet is not_found.",
		setup: func(*flag.FlagSet) func(*cli, []string) error {
			return func(c *cli, pos []string) error {
				id, err := onePositional(pos, "asset ID")
				if err != nil {
					return err
				}
				return c.printDeletionRecord(id)
			}
		},
	},
}

type waitFlags struct {
	wait    bool
	timeout time.Duration
}

func addWaitFlags(fs *flag.FlagSet) *waitFlags {
	w := &waitFlags{}
	fs.BoolVar(&w.wait, "wait", false, "poll until the asset reaches its final state")
	fs.DurationVar(&w.timeout, "wait-timeout", 30*time.Minute, "give up waiting after this long (exit code 8)")
	return w
}

func (c *cli) printf(format string, a ...any) { _, _ = fmt.Fprintf(c.stdout, format, a...) }

func (c *cli) getAsset(ctx context.Context, id string) (apiclient.Asset, []byte, error) {
	ctx, cancel := c.ctx(ctx, 1)
	defer cancel()
	resp, err := c.api.GetAsset(ctx, id) //nolint:bodyclose // finish closes it
	var a apiclient.Asset
	raw, err := c.finish(resp, err, &a)
	return a, raw, err
}

// printAsset shows an asset: the raw document with --json, otherwise its ID and state.
func (c *cli) printAsset(a apiclient.Asset, raw []byte) error {
	if c.json {
		c.printJSON(raw)
	} else if c.idOnly {
		c.printf("%s\n", a.Id)
	} else {
		c.printf("%s  %s\n", a.Id, a.State)
	}
	return nil
}

// finishAsset ends a command that produced an asset: it waits for ready when asked, then prints.
func (c *cli) finishAsset(a apiclient.Asset, raw []byte, w *waitFlags) error {
	if w.wait {
		final, err := c.waitFor(context.Background(), a.Id, w, func(a apiclient.Asset) (bool, error) {
			switch a.State {
			case apiclient.AssetStateReady:
				return true, nil
			case apiclient.AssetStateFailed, apiclient.AssetStateDeleting, apiclient.AssetStateDeleted:
				code := ""
				if a.FailureCode != nil {
					code = " (" + *a.FailureCode + ")"
				}
				return false, &cliError{code: exitIncomplete, kind: "incomplete", msg: fmt.Sprintf("asset %s is %s%s", a.Id, a.State, code)}
			}
			return false, nil
		})
		if err != nil {
			return err
		}
		a = final.asset
		raw = final.raw
	}
	return c.printAsset(a, raw)
}

type waited struct {
	asset apiclient.Asset
	raw   []byte
}

// waitFor polls the asset with growing pauses until done says so, the wait times out (exit 8) or
// done fails. Transient network errors and unavailable answers are retried until the deadline.
func (c *cli) waitFor(parent context.Context, id string, w *waitFlags, done func(apiclient.Asset) (bool, error)) (waited, error) {
	deadline := time.Now().Add(w.timeout)
	pause := pollMin
	last := ""
	for {
		a, raw, err := c.getAsset(parent, id)
		var ce *cliError
		switch {
		case err == nil:
			if last != string(a.State) {
				last = string(a.State)
				c.diag("%s is %s", a.Id, a.State)
			}
			ok, derr := done(a)
			if derr != nil {
				return waited{}, derr
			}
			if ok {
				return waited{a, raw}, nil
			}
		case asCLIError(err, &ce) && ce.code == exitUnavailable:
			c.diag("%v; retrying", err)
		default:
			return waited{}, err
		}
		if time.Now().Add(pause).After(deadline) {
			return waited{}, &cliError{
				code: exitIncomplete, kind: "incomplete",
				msg: fmt.Sprintf("timed out after %s waiting for %s (last state %q)", w.timeout, id, last),
			}
		}
		time.Sleep(pause)
		pause = min(pause*3/2, pollMax)
	}
}

func (c *cli) printDeletionRecord(id string) error {
	ctx, cancel := c.ctx(context.Background(), 1)
	defer cancel()
	resp, err := c.api.GetAssetDeletionRecord(ctx, id) //nolint:bodyclose // finish closes it
	raw, err := c.finish(resp, err, nil)
	if err != nil {
		return err
	}
	c.printJSON([]byte(strings.TrimSpace(string(raw))))
	return nil
}

func asCLIError(err error, target **cliError) bool { return errors.As(err, target) }

func indentJSON(raw []byte) []byte {
	var b bytes.Buffer
	if json.Indent(&b, raw, "", "  ") != nil {
		return raw
	}
	return b.Bytes()
}
