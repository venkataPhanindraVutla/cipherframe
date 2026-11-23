// Command cipherframe is the Cipherframe command line tool. It currently has one working
// subcommand, verify, which checks files against a signed manifest, or a signed deletion record,
// with public keys only (ADR 0039). It is a static binary with no server dependencies.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/venkataPhanindraVutla/cipherframe/internal/version"
)

const usage = `cipherframe: Cipherframe command line tool

Usage:
  cipherframe verify --manifest m.json (--keys keys.json | --keys-url URL) [--variant original|masked]
                     [--path P] [--root DIR] [--json] [--timestamp ts.json [--tsa-ca ca.pem]] <file-or-dir>...
  cipherframe verify --manifest m.json (--keys keys.json | --keys-url URL) --proof p.json <file>
  cipherframe verify --deletion-record r.json (--keys keys.json | --keys-url URL) [--json]
  cipherframe upload FILE [--wait] [--mask-faces] [--ttl 30d]
  cipherframe status ASSET_ID | inspect ASSET_ID | list [--limit N] [--cursor C]
  cipherframe process ASSET_ID [--wait]
  cipherframe delete ASSET_ID [--wait] | deletion-record ASSET_ID | rekey ASSET_ID
  cipherframe session create ASSET [--viewer ID] [--variant V] [--show-token] | show ID | revoke ID|--viewer V|--asset A
  cipherframe verify-file ASSET FILE [--path P] [--variant V] | proof ASSET PATH [--variant V]
  cipherframe subtitles import ASSET FILE --language L [--label T] [--default] | list ASSET | delete ASSET ID
  cipherframe brand set-logo FILE [--corner C] [--opacity N] | show | remove
  cipherframe keys rotate-api-key KEY_ID [--overlap 10m]
  cipherframe webhooks list [--endpoint ID] [--status S] | replay DELIVERY_ID | replay --endpoint ID --dead
  cipherframe audit export [--since T] [--until T]
  cipherframe version
  cipherframe help [command]

Commands that call the server take --server (or CIPHERFRAME_SERVER), the API key from
CIPHERFRAME_API_KEY or --api-key-file (never a flag value), --json and --timeout; flags may
follow the arguments. Run cipherframe help COMMAND for a command's flags.

Exit codes for verify: 0 all ours, 1 any modified, 2 any cannot say (none modified), 3 usage error.
A deletion record is ours (exit 0) when a trusted key signed it, otherwise cannot say (exit 2).
` + exitCodeHelp

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "version", "--version":
		info := version.Get()
		_, _ = fmt.Fprintf(stdout, "cipherframe %s %s\n", info.Version, info.GoVersion)
		return 0
	case "help", "-h", "--help":
		if len(args) >= 2 {
			if cmd, ok := serverCommands()[args[1]]; ok {
				return cmd.run(append(append([]string{}, args[2:]...), "-h"), stdout, stderr)
			}
		}
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	}
	if cmd, ok := serverCommands()[args[0]]; ok {
		return cmd.run(args[1:], stdout, stderr)
	}
	_, _ = fmt.Fprintf(stderr, "cipherframe: unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

func serverCommands() map[string]command {
	m := map[string]command{uploadCommand.name: uploadCommand}
	for _, c := range append(assetCommands, restCommands...) {
		m[c.name] = c
	}
	return m
}
