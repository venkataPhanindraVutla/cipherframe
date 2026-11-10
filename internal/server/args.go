package server

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// Command is the parsed command line.
type Command struct {
	// MigrateOnly is set by the `migrate` subcommand: apply migrations and exit.
	MigrateOnly bool
	// Options are the serve options; unused when MigrateOnly is set.
	Options Options
}

// Usage is the help text.
const Usage = `Usage:
  cipherframe-server --role=<roles> [--migrate]
  cipherframe-server migrate

Roles is a comma-separated list of api, edge and worker, for example --role=api,edge.
  --role     roles to run (required)
  --migrate  apply pending database migrations before serving (default off)
  migrate    apply pending database migrations and exit

Configuration is read from CIPHERFRAME_* environment variables (docs/usage.md).
`

// ErrHelp is returned by ParseArgs when help was requested.
var ErrHelp = flag.ErrHelp

// ParseArgs parses the arguments after the program name. Flag parse errors are returned as plain
// errors and nothing is written to the console, so the caller decides how to report them.
func ParseArgs(args []string) (Command, error) {
	if len(args) > 0 && args[0] == "migrate" {
		if len(args) > 1 {
			return Command{}, errors.New("migrate takes no arguments")
		}
		return Command{MigrateOnly: true}, nil
	}

	fs := flag.NewFlagSet("cipherframe-server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	role := fs.String("role", "", "roles to run")
	migrate := fs.Bool("migrate", false, "apply pending migrations before serving")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return Command{}, ErrHelp
		}
		return Command{}, err
	}
	if fs.NArg() > 0 {
		return Command{}, fmt.Errorf("unexpected argument %q", sanitize(strings.Join(fs.Args(), " ")))
	}
	roles, err := ParseRoles(*role)
	if err != nil {
		return Command{}, err
	}
	return Command{Options: Options{Roles: roles, Migrate: *migrate}}, nil
}
