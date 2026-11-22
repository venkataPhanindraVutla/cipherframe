package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/apiclient"
)

const auditPageSize = 500

var auditCommand = command{
	name: "audit",
	help: "The tenant's audit log (needs the admin scope).",
	subs: []command{{
		name: "audit export", synopsis: "audit export [--since T] [--until T] [flags]",
		help: "Write the audit events of the tenant to stdout as NDJSON, one event per line, oldest first,\n" +
			"following every page. --since is inclusive and --until exclusive (RFC 3339). Events hold no\n" +
			"secrets: an ID, an action, a target label, the acting client and key IDs and the request ID.\n" +
			"The output is always NDJSON; --json changes only how an error is printed.",
		setup: func(fs *flag.FlagSet) func(*cli, []string) error {
			since := fs.String("since", "", "only events at or after this time (RFC 3339)")
			until := fs.String("until", "", "only events before this time (RFC 3339)")
			return func(c *cli, pos []string) error {
				if len(pos) != 0 {
					return usageErr("audit export takes no arguments")
				}
				limit := auditPageSize
				p := &apiclient.ListAuditEventsParams{Limit: &limit}
				for _, f := range []struct {
					name, val string
					dst       **time.Time
				}{{"since", *since, &p.Since}, {"until", *until, &p.Until}} {
					if f.val == "" {
						continue
					}
					t, err := time.Parse(time.RFC3339, f.val)
					if err != nil {
						return usageErr("--%s is not an RFC 3339 time", f.name)
					}
					*f.dst = &t
				}
				for {
					var page struct {
						Items      []json.RawMessage `json:"items"`
						NextCursor *string           `json:"next_cursor"`
					}
					if _, err := c.call(2, func(ctx context.Context) (*http.Response, error) {
						return c.api.ListAuditEvents(ctx, p)
					}, &page); err != nil {
						return err
					}
					for _, it := range page.Items {
						var line bytes.Buffer
						if err := json.Compact(&line, it); err != nil {
							return &cliError{code: exitAPI, kind: "bad_response", msg: "the server's answer is not the expected JSON"}
						}
						line.WriteByte('\n')
						_, _ = c.stdout.Write(line.Bytes())
					}
					if page.NextCursor == nil {
						return nil
					}
					p.After = page.NextCursor
				}
			}
		},
	}},
}
