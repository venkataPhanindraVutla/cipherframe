package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/venkataPhanindraVutla/cipherframe/internal/apiclient"
)

// readInput reads a local file of at most limit bytes. The name is never sent to the server.
func readInput(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name) //nolint:gosec // the operator names the file
	if err != nil {
		return nil, usageErr("read the file: %v", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, usageErr("read the file: %v", err)
	}
	if int64(len(b)) > limit {
		return nil, usageErr("the file is larger than %d bytes", limit)
	}
	return b, nil
}

// multipartBody builds a form with the text fields (empty values skipped) and one file part. The
// part carries a fixed file name: the local one is never sent.
func multipartBody(fields map[string]string, file []byte) (io.Reader, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if v == "" {
			continue
		}
		if err := w.WriteField(k, v); err != nil {
			return nil, "", err
		}
	}
	part, err := w.CreateFormFile("file", "upload")
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(file); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return &buf, w.FormDataContentType(), nil
}

const maxSubtitleBytes = 4 << 20 // the transcript limit; the server enforces 2 MB for a WebVTT or SRT file

func (c *cli) printTrack(t apiclient.SubtitleTrack) {
	def := ""
	if t.Default {
		def = "  default"
	}
	c.printf("%s  %-8s %-20s %6d cues  %s%s\n", t.Id, t.Language, t.Label, t.CueCount, t.Origin, def)
}

var subtitlesCommand = command{
	name: "subtitles",
	help: "Subtitle tracks of a ready asset: import a WebVTT or SRT file (or a JSON transcript), list,\n" +
		"delete. The server checks and rewrites every file; the local file name is never sent.",
	subs: []command{
		{
			name: "subtitles import", synopsis: "subtitles import ASSET FILE --language L [--label TEXT] [--default] [flags]",
			help: "Add a track. A .json FILE is a transcript, sent to the transcripts endpoint: either\n" +
				"{\"cues\":[...]} or a bare list of {\"start\",\"end\",\"text\",\"speaker\"} with times in seconds.\n" +
				"Any other FILE is WebVTT or SRT (the server reads the format from the content). The label\n" +
				"defaults to the language tag. Prints the new track.",
			setup: func(fs *flag.FlagSet) func(*cli, []string) error {
				lang := fs.String("language", "", "BCP 47 tag such as en or pt-BR (required)")
				label := fs.String("label", "", "the name a player shows (default: the language)")
				def := fs.Bool("default", false, "players select this track unasked")
				return func(c *cli, pos []string) error {
					if len(pos) != 2 {
						return usageErr("expected an asset ID and a file")
					}
					if *lang == "" {
						return usageErr("--language is required")
					}
					if *label == "" {
						*label = *lang
					}
					asset, file := pos[0], pos[1]
					data, err := readInput(file, maxSubtitleBytes)
					if err != nil {
						return err
					}
					var t apiclient.SubtitleTrack
					var raw []byte
					if strings.EqualFold(filepath.Ext(file), ".json") {
						req, err := transcriptRequest(data, *lang, *label, *def)
						if err != nil {
							return err
						}
						raw, err = c.call(1, func(ctx context.Context) (*http.Response, error) {
							return c.api.ImportAssetTranscript(ctx, asset, req)
						}, &t)
						if err != nil {
							return err
						}
					} else {
						fields := map[string]string{"language": *lang, "label": *label}
						if *def {
							fields["default"] = "true"
						}
						body, ctype, err := multipartBody(fields, data)
						if err != nil {
							return err
						}
						raw, err = c.call(2, func(ctx context.Context) (*http.Response, error) {
							return c.api.CreateAssetSubtitleWithBody(ctx, asset, ctype, body)
						}, &t)
						if err != nil {
							return err
						}
					}
					c.result(raw, func() { c.printTrack(t) })
					return nil
				}
			},
		},
		{
			name: "subtitles list", synopsis: "subtitles list ASSET [flags]",
			help: "List the asset's tracks, oldest first.",
			setup: func(*flag.FlagSet) func(*cli, []string) error {
				return func(c *cli, pos []string) error {
					asset, err := onePositional(pos, "asset ID")
					if err != nil {
						return err
					}
					var out apiclient.SubtitleList
					raw, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
						return c.api.ListAssetSubtitles(ctx, asset)
					}, &out)
					if err != nil {
						return err
					}
					c.result(raw, func() {
						for _, t := range out.Items {
							c.printTrack(t)
						}
					})
					return nil
				}
			},
		},
		{
			name: "subtitles delete", synopsis: "subtitles delete ASSET SUBTITLE_ID [flags]",
			help: "Delete one track (the manifest is signed again).",
			setup: func(*flag.FlagSet) func(*cli, []string) error {
				return func(c *cli, pos []string) error {
					if len(pos) != 2 {
						return usageErr("expected an asset ID and a subtitle ID")
					}
					if _, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
						return c.api.DeleteAssetSubtitle(ctx, pos[0], pos[1])
					}, nil); err != nil {
						return err
					}
					c.done("deleted", "deleted")
					return nil
				}
			},
		},
	},
}

// transcriptRequest reads a transcript file: {"cues":[...]} or a bare list of cues.
func transcriptRequest(data []byte, lang, label string, def bool) (apiclient.ImportTranscriptRequest, error) {
	var req apiclient.ImportTranscriptRequest
	if err := json.Unmarshal(data, &req); err != nil {
		if err := json.Unmarshal(data, &req.Cues); err != nil {
			return req, usageErr("the transcript is not JSON of the form {\"cues\":[{\"start\":0,\"end\":1,\"text\":\"...\"}]}")
		}
	}
	if len(req.Cues) == 0 {
		return req, usageErr("the transcript has no cues")
	}
	req.Language, req.Label = lang, label
	req.Default = nil
	if def {
		req.Default = &def
	}
	return req, nil
}

var brandCommand = command{
	name: "brand",
	help: "The tenant's brand logo (needs the admin scope). The logo is burned into videos when they are\n" +
		"transcoded: a new logo, a changed placement or a removal applies only to assets whose processing\n" +
		"starts afterwards, never to assets that are ready.",
	subs: []command{
		{
			name: "brand set-logo", synopsis: "brand set-logo FILE [--corner C] [--opacity N] [flags]",
			help: "Upload a PNG (at most 256 KB, 16 to 1024 pixels a side) as the current logo. The server\n" +
				"rewrites the image. Not retroactive: only assets processed from now on get it.",
			setup: func(fs *flag.FlagSet) func(*cli, []string) error {
				corner := fs.String("corner", "", "top_left, top_right, bottom_left or bottom_right (default bottom_right)")
				opacity := fs.Int("opacity", 0, "percent, 10 to 100 (default 100)")
				return func(c *cli, pos []string) error {
					file, err := onePositional(pos, "file")
					if err != nil {
						return err
					}
					switch *corner {
					case "", "top_left", "top_right", "bottom_left", "bottom_right":
					default:
						return usageErr("--corner is top_left, top_right, bottom_left or bottom_right")
					}
					if *opacity != 0 && (*opacity < 10 || *opacity > 100) {
						return usageErr("--opacity is a whole number from 10 to 100")
					}
					data, err := readInput(file, 1<<20)
					if err != nil {
						return err
					}
					fields := map[string]string{"corner": *corner}
					if *opacity != 0 {
						fields["opacity"] = strconv.Itoa(*opacity)
					}
					body, ctype, err := multipartBody(fields, data)
					if err != nil {
						return err
					}
					return c.logoResult(func(ctx context.Context) (*http.Response, error) {
						return c.api.PutBrandLogoWithBody(ctx, ctype, body)
					}, 2)
				}
			},
		},
		{
			name: "brand show", synopsis: "brand show [flags]",
			help: "Print the current logo's metadata (never the image). Not found when there is none.",
			setup: func(*flag.FlagSet) func(*cli, []string) error {
				return func(c *cli, pos []string) error {
					if len(pos) != 0 {
						return usageErr("brand show takes no arguments")
					}
					return c.logoResult(func(ctx context.Context) (*http.Response, error) { return c.api.GetBrandLogo(ctx) }, 1)
				}
			},
		},
		{
			name: "brand remove", synopsis: "brand remove [flags]",
			help: "Remove the logo setting. Assets already ready keep the logo burned into their video.",
			setup: func(*flag.FlagSet) func(*cli, []string) error {
				return func(c *cli, pos []string) error {
					if len(pos) != 0 {
						return usageErr("brand remove takes no arguments")
					}
					if _, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
						return c.api.DeleteBrandLogo(ctx)
					}, nil); err != nil {
						return err
					}
					c.done("removed", "removed")
					return nil
				}
			},
		},
	},
}

func (c *cli) logoResult(do func(ctx context.Context) (*http.Response, error), mult int) error {
	var l apiclient.BrandLogo
	raw, err := c.call(mult, do, &l)
	if err != nil {
		return err
	}
	c.result(raw, func() {
		c.printf("version %s  %dx%d  %s  %d%%  enabled=%t  updated %s\n", l.Version, l.Width, l.Height, l.Corner,
			l.OpacityPercent, l.Enabled, l.UpdatedAt.UTC().Format(time.RFC3339))
	})
	return nil
}

var keysCommand = command{
	name: "keys",
	help: "API keys. rotate-api-key replaces a key's secret and shows the new key once. There is no\n" +
		"keys rewrap: re-wrapping content keys under a new KEK is a server administration job with no\n" +
		"HTTP call, run on the server as cipherframe-server admin kms-rewrap (see docs/usage.md).",
	gaps: map[string]string{"rewrap": "the API has no key re-wrap call; run it on the server: cipherframe-server admin kms-rewrap [--wait] (docs/usage.md)"},
	subs: []command{{
		name: "keys rotate-api-key", synopsis: "keys rotate-api-key KEY_ID [--overlap 10m] [flags]",
		help: "Replace the secret of API key KEY_ID (same ID, client and scopes). The old secret keeps working\n" +
			"for --overlap (0 to 24h, default 10m). The NEW KEY IS SHOWN ONCE, on stdout only (the whole\n" +
			"response with --json); the key ID and the overlap end go to stderr with a warning. Store it at\n" +
			"once: it cannot be shown again. Use it as CIPHERFRAME_API_KEY or put it in an --api-key-file.",
		setup: func(fs *flag.FlagSet) func(*cli, []string) error {
			overlap := fs.Duration("overlap", -1, "how long the old key keeps working, 0 to 24h (default: the server's, 10m)")
			return func(c *cli, pos []string) error {
				id, err := onePositional(pos, "key ID")
				if err != nil {
					return err
				}
				req := apiclient.RotateKeyRequest{}
				if *overlap >= 0 {
					if *overlap > 24*time.Hour {
						return usageErr("--overlap is at most 24h")
					}
					s := int(*overlap / time.Second)
					req.OverlapSeconds = &s
				}
				var k apiclient.CreatedApiKey
				raw, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
					return c.api.RotateKey(ctx, id, req)
				}, &k)
				if err != nil {
					return err
				}
				c.secrets = append(c.secrets, k.Key)
				c.diag("warning: the new key is shown only now and cannot be shown again; store it before closing this terminal")
				if k.PreviousValidUntil != nil {
					c.diag("the previous key of %s works until %s", k.Id, k.PreviousValidUntil.UTC().Format(time.RFC3339))
				}
				c.result(raw, func() { c.printf("%s\n", k.Key) })
				return nil
			}
		},
	}},
}

var webhooksCommand = command{
	name: "webhooks",
	help: "Webhook deliveries (needs the webhooks:manage scope). Replaying sends the same event ID again,\n" +
		"so receivers must deduplicate on it.",
	subs: []command{
		{
			name: "webhooks list", synopsis: "webhooks list [--endpoint ID] [--status pending|succeeded|dead] [--limit N] [--cursor C] [flags]",
			help: "List deliveries, newest first, one page at a time (--status dead is the dead-letter list).\n" +
				"When more remain the next cursor is printed (stderr, or next_cursor with --json).",
			setup: func(fs *flag.FlagSet) func(*cli, []string) error {
				endpoint := fs.String("endpoint", "", "only deliveries to this endpoint")
				status := fs.String("status", "", "pending, succeeded or dead")
				limit := fs.Int("limit", 0, "page size, 1 to 100 (default: the server's, 50)")
				cursor := fs.String("cursor", "", "the next_cursor of the previous page")
				return func(c *cli, pos []string) error {
					if len(pos) != 0 {
						return usageErr("webhooks list takes no arguments")
					}
					p := &apiclient.ListWebhookDeliveriesParams{}
					if *endpoint != "" {
						p.EndpointId = endpoint
					}
					switch apiclient.WebhookDeliveryStatus(*status) {
					case "":
					case apiclient.WebhookDeliveryStatusPending, apiclient.WebhookDeliveryStatusSucceeded, apiclient.WebhookDeliveryStatusDead:
						s := apiclient.WebhookDeliveryStatus(*status)
						p.Status = &s
					default:
						return usageErr("--status is pending, succeeded or dead")
					}
					if *limit != 0 {
						p.Limit = limit
					}
					if *cursor != "" {
						p.Cursor = cursor
					}
					var out apiclient.WebhookDeliveryList
					raw, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
						return c.api.ListWebhookDeliveries(ctx, p)
					}, &out)
					if err != nil {
						return err
					}
					c.result(raw, func() {
						for _, d := range out.Items {
							c.printf("%s  %-9s %-28s attempts %d  %s\n", d.Id, d.Status, d.Kind, d.Attempts, d.CreatedAt.UTC().Format(time.RFC3339))
						}
						if out.NextCursor != nil {
							c.diag("more: --cursor %s", *out.NextCursor)
						}
					})
					return nil
				}
			},
		},
		{
			name: "webhooks replay", synopsis: "webhooks replay DELIVERY_ID | --endpoint ID --dead [flags]",
			help: "Queue a delivered or dead-lettered delivery again with a fresh attempt budget (a delivery\n" +
				"that is still pending is a conflict), or with --endpoint ID --dead every dead-lettered\n" +
				"delivery of that endpoint, printing how many.",
			setup: func(fs *flag.FlagSet) func(*cli, []string) error {
				endpoint := fs.String("endpoint", "", "the endpoint whose dead deliveries to replay (with --dead)")
				dead := fs.Bool("dead", false, "replay every dead-lettered delivery of --endpoint")
				return func(c *cli, pos []string) error {
					if *dead {
						if *endpoint == "" || len(pos) != 0 {
							return usageErr("--dead takes --endpoint ID and no delivery ID")
						}
						var out apiclient.ReplayedDeliveries
						raw, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
							return c.api.ReplayDeadWebhookDeliveries(ctx, *endpoint)
						}, &out)
						if err != nil {
							return err
						}
						c.result(raw, func() { c.printf("queued %d delivery(ies) again\n", out.Replayed) })
						return nil
					}
					id, err := onePositional(pos, "delivery ID")
					if err != nil || *endpoint != "" {
						return usageErr("give one delivery ID, or --endpoint ID --dead")
					}
					var u openapi_types.UUID
					if u.UnmarshalText([]byte(id)) != nil {
						return usageErr("a delivery ID is a UUID")
					}
					var d apiclient.WebhookDelivery
					raw, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
						return c.api.ReplayWebhookDelivery(ctx, u)
					}, &d)
					if err != nil {
						return err
					}
					c.result(raw, func() { c.printf("%s  %s\n", d.Id, d.Status) })
					return nil
				}
			},
		},
	},
}
