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
  cipherframe version
  cipherframe help

Exit codes for verify: 0 all ours, 1 any modified, 2 any cannot say (none modified), 3 usage error.
A deletion record is ours (exit 0) when a trusted key signed it, otherwise cannot say (exit 2).
`

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
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "cipherframe: unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}
