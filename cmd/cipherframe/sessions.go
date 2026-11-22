package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"net/http"
	"net/url"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/apiclient"
)

var restCommands = []command{sessionCommand, verifyFileCommand, proofCommand, subtitlesCommand, brandCommand, keysCommand, webhooksCommand}

func checkVariant(v string) error {
	if v != "" && v != "original" && v != "masked" {
		return usageErr("--variant is original or masked")
	}
	return nil
}

var sessionCommand = command{
	name: "session",
	help: "Playback sessions: create one for a viewer, look one up, revoke by ID, viewer or asset.\n" +
		"A session ID is a capability: it is printed as a result, never in errors or logs.\n" +
		"The API has no session listing, so there is no session list; use session show ID, or the\n" +
		"access log and anomaly events of the API (ADR 0051).",
	gaps: map[string]string{"list": "the API has no call that lists playback sessions; use session show ID, or revoke by --viewer or --asset"},
	subs: []command{
		{
			name: "session create", synopsis: "session create ASSET [--viewer ID] [--variant original|masked] [--show-token] [flags]",
			help: "Start a playback session on a ready asset and print what an integrator needs: the session ID,\n" +
				"the manifest URL on the edge (the edge URL the API returns), the expiry and the heartbeat\n" +
				"interval. The playback token is NOT printed unless you pass --show-token (stdout only; it is\n" +
				"never in errors or logs). When the tenant sends tokens in URLs, the token is cut from the\n" +
				"printed manifest URL too unless --show-token is given. --viewer is a pseudonymous ID you\n" +
				"choose (never an email address); by default a random one is made, so the per-viewer session\n" +
				"limit is not used up by test runs.",
			setup: func(fs *flag.FlagSet) func(*cli, []string) error {
				viewer := fs.String("viewer", "", "pseudonymous viewer ID (default: a random cli- ID)")
				variant := fs.String("variant", "", "original or masked (default: the asset's default)")
				show := fs.Bool("show-token", false, "also print the playback token (stdout, shown only once)")
				return func(c *cli, pos []string) error {
					asset, err := onePositional(pos, "asset ID")
					if err != nil {
						return err
					}
					if err := checkVariant(*variant); err != nil {
						return err
					}
					req := apiclient.CreatePlaybackSessionRequest{AssetId: asset, ViewerId: *viewer}
					if *viewer == "" {
						var b [8]byte
						_, _ = rand.Read(b[:])
						req.ViewerId = "cli-" + hex.EncodeToString(b[:])
					}
					if *variant != "" {
						v := apiclient.Variant(*variant)
						req.Variant = &v
					}
					var s apiclient.CreatedPlaybackSession
					raw, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
						return c.api.CreatePlaybackSession(ctx, req)
					}, &s)
					if err != nil {
						return err
					}
					if !*show {
						raw = redactSession(raw)
						s.ManifestUrl = stripToken(s.ManifestUrl)
					}
					c.result(raw, func() {
						c.printf("session      %s\nvariant      %s\nmanifest     %s\nexpires      %s\nheartbeat    every %ds\n",
							s.SessionId, s.Variant, s.ManifestUrl, s.SessionExpiresAt.UTC().Format(time.RFC3339), s.HeartbeatIntervalSeconds)
						if *show {
							c.printf("token        %s\ntoken_expires %s\n", s.Token, s.TokenExpiresAt.UTC().Format(time.RFC3339))
						}
					})
					if !*show && s.TokenTransport == apiclient.Url {
						c.diag("the manifest URL needs its token (token_transport is url): rerun with --show-token to get it")
					}
					return nil
				}
			},
		},
		{
			name: "session show", synopsis: "session show SESSION_ID [flags]",
			help: "Print the state of one session. It never includes a token.",
			setup: func(*flag.FlagSet) func(*cli, []string) error {
				return func(c *cli, pos []string) error {
					id, err := onePositional(pos, "session ID")
					if err != nil {
						return err
					}
					c.secrets = append(c.secrets, id)
					var s apiclient.PlaybackSessionStatus
					raw, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
						return c.api.GetPlaybackSession(ctx, id)
					}, &s)
					if err != nil {
						return err
					}
					c.result(raw, func() { c.printStatus(s) })
					return nil
				}
			},
		},
		{
			name: "session revoke", synopsis: "session revoke SESSION_ID | --viewer V | --asset A [--reason R] [flags]",
			help: "Revoke one session by ID, or every active session of a viewer, of an asset or (both flags)\n" +
				"of that viewer on that asset. There is no tenant-wide revoke. Takes effect at once for\n" +
				"playlists, the key and heartbeats; segments already covered by a token work until it expires\n" +
				"but cannot be decrypted. The reason is stored with the session: no personal data.",
			setup: func(fs *flag.FlagSet) func(*cli, []string) error {
				viewer := fs.String("viewer", "", "revoke the active sessions of this viewer ID")
				asset := fs.String("asset", "", "revoke the active sessions on this asset")
				reason := fs.String("reason", "", "why, at most 200 characters (stored; no personal data)")
				return func(c *cli, pos []string) error {
					filtered := *viewer != "" || *asset != ""
					if len(pos) > 1 || (len(pos) == 1) == filtered {
						return usageErr("give one session ID, or --viewer and/or --asset")
					}
					var rs *string
					if *reason != "" {
						rs = reason
					}
					if filtered {
						req := apiclient.RevokePlaybackSessionsRequest{Reason: rs}
						if *viewer != "" {
							req.ViewerId = viewer
						}
						if *asset != "" {
							req.AssetId = asset
						}
						var out apiclient.RevokedPlaybackSessions
						raw, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
							return c.api.RevokePlaybackSessions(ctx, req)
						}, &out)
						if err != nil {
							return err
						}
						c.result(raw, func() { c.printf("revoked %d session(s)\n", out.Revoked) })
						return nil
					}
					c.secrets = append(c.secrets, pos[0])
					var s apiclient.PlaybackSessionStatus
					raw, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
						return c.api.RevokePlaybackSession(ctx, pos[0], apiclient.RevokePlaybackSessionRequest{Reason: rs})
					}, &s)
					if err != nil {
						return err
					}
					c.result(raw, func() { c.printStatus(s) })
					return nil
				}
			},
		},
	},
}

func (c *cli) printStatus(s apiclient.PlaybackSessionStatus) {
	c.printf("state        %s\nasset        %s\nviewer       %s\ncreated      %s\nlast beat    %s\nexpires      %s\n",
		s.State, s.AssetId, s.ViewerId, s.CreatedAt.UTC().Format(time.RFC3339), s.LastHeartbeatAt.UTC().Format(time.RFC3339),
		s.SessionExpiresAt.UTC().Format(time.RFC3339))
	if s.RevokeReason != nil {
		c.printf("reason       %s\n", *s.RevokeReason)
	}
}

// redactSession drops the playback token, and the token in the manifest URL, from a create response.
func redactSession(raw []byte) []byte {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return []byte(`{}`)
	}
	delete(m, "token")
	var u string
	if json.Unmarshal(m["manifest_url"], &u) == nil {
		m["manifest_url"], _ = json.Marshal(stripToken(u))
	}
	out, _ := json.Marshal(m)
	return out
}

// stripToken removes the t query parameter (the playback token) from a manifest URL. A URL that
// does not parse is dropped rather than risk printing a token.
func stripToken(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Del("t")
	u.RawQuery = q.Encode()
	return u.String()
}
