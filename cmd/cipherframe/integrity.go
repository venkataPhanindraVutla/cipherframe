package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"net/http"

	"github.com/venkataPhanindraVutla/cipherframe/internal/apiclient"
)

var verifyFileCommand = command{
	name: "verify-file", synopsis: "verify-file ASSET FILE [--path P] [--variant original|masked] [flags]",
	help: "Hash FILE here (the file never leaves this machine) and ask the server whether it is one of\n" +
		"ASSET's artifacts. With --path P the hash is compared with that manifest path (variant default\n" +
		"original), so a file that claims to be P but differs is reported modified. Without --path the\n" +
		"tenant's artifacts are searched by hash, and a match in another asset is cannot say.\n" +
		"Exit codes follow verify: 0 ours, 1 modified, 2 cannot say (never a verdict that a file is fake).\n" +
		"With --json the server's answer is printed unchanged.",
	setup: func(fs *flag.FlagSet) func(*cli, []string) error {
		path := fs.String("path", "", "manifest path of the artifact the file claims to be, such as 720p/seg-0.m4s")
		variant := fs.String("variant", "", "original or masked (needs --path)")
		return func(c *cli, pos []string) error {
			if len(pos) != 2 {
				return usageErr("expected an asset ID and a file")
			}
			asset, file := pos[0], pos[1]
			if err := checkVariant(*variant); err != nil {
				return err
			}
			if *path == "" && *variant != "" {
				return usageErr("--variant needs --path")
			}
			sum, err := hashFile(file)
			if err != nil {
				return usageErr("read the file: %v", err)
			}
			req := apiclient.VerifyRequest{Sha256: hex.EncodeToString(sum[:])}
			if *path != "" {
				req.AssetId, req.Path = &asset, path
				if *variant != "" {
					v := apiclient.ArtifactVariant(*variant)
					req.Variant = &v
				}
			}
			var out apiclient.VerifyResult
			raw, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
				return c.api.VerifyArtifact(ctx, req)
			}, &out)
			if err != nil {
				return err
			}
			outcome := out.Outcome
			other := outcome == apiclient.Ours && out.AssetId != nil && *out.AssetId != asset
			if other {
				outcome = apiclient.CannotSay // ours, but not an artifact of this asset
			}
			c.result(raw, func() {
				switch {
				case other:
					c.printf("cannot_say  the file is an artifact of another asset\n")
				case outcome == apiclient.Ours && out.Path != nil:
					c.printf("ours        %s  (verified)\n", *out.Path)
				case out.Reason != nil:
					c.printf("%s  %s\n", outcome, *out.Reason)
				default:
					c.printf("%s\n", outcome)
				}
			})
			switch outcome {
			case apiclient.Ours:
				return nil
			case apiclient.Modified:
				return &cliError{code: exitModified, kind: "modified", quiet: true}
			}
			return &cliError{code: exitCannot, kind: "cannot_say", quiet: true}
		}
	},
}

var proofCommand = command{
	name: "proof", synopsis: "proof ASSET PATH [--variant original|masked] [flags]",
	help: "Fetch the inclusion proof of one artifact, PATH being its manifest path (such as\n" +
		"720p/seg-0.m4s). The proof JSON is printed on stdout (indented without --json) exactly as\n" +
		"cipherframe verify --manifest m.json --keys k.json --proof p.json FILE expects it.",
	setup: func(fs *flag.FlagSet) func(*cli, []string) error {
		variant := fs.String("variant", "", "original or masked (default original)")
		return func(c *cli, pos []string) error {
			if len(pos) != 2 {
				return usageErr("expected an asset ID and a manifest path")
			}
			if err := checkVariant(*variant); err != nil {
				return err
			}
			p := &apiclient.GetAssetProofParams{Path: &pos[1]}
			if *variant != "" {
				v := apiclient.ArtifactVariant(*variant)
				p.Variant = &v
			}
			raw, err := c.call(1, func(ctx context.Context) (*http.Response, error) {
				return c.api.GetAssetProof(ctx, pos[0], p)
			}, nil)
			if err != nil {
				return err
			}
			if !c.json {
				raw = indentJSON(raw)
			}
			c.printJSON(bytes.TrimSpace(raw))
			return nil
		}
	},
}
