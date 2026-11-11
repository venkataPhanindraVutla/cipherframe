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
	// Admin is set by the `admin` subcommands; nil otherwise.
	Admin *AdminCommand
	// Options are the serve options; unused when MigrateOnly or Admin is set.
	Options Options
}

// Admin actions.
const (
	AdminBootstrap   = "bootstrap"
	AdminPepperUsage = "pepper-usage"
)

// AdminCommand is a parsed `cipherframe-server admin ...` command.
type AdminCommand struct {
	// Action is AdminBootstrap or AdminPepperUsage.
	Action string
	// TenantName and ClientName are the bootstrap names.
	TenantName, ClientName string
}

// Usage is the help text.
const Usage = `Usage:
  cipherframe-server --role=<roles> [--migrate]
  cipherframe-server migrate
  cipherframe-server admin bootstrap --tenant-name NAME --client-name NAME
  cipherframe-server admin pepper-usage

Roles is a comma-separated list of api, edge and worker, for example --role=api,edge.
  --role     roles to run (required)
  --migrate  apply pending database migrations before serving (default off)
  migrate    apply pending database migrations and exit
  admin bootstrap     create a tenant, a client and an admin API key in one transaction;
                      prints only the key on stdout (everything else goes to the log on stderr)
  admin pepper-usage  print how many active API keys use each pepper version

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

	if len(args) > 0 && args[0] == "admin" {
		return parseAdmin(args[1:])
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

func parseAdmin(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, errors.New("admin needs a subcommand: bootstrap or pepper-usage")
	}
	switch args[0] {
	case AdminPepperUsage:
		if len(args) > 1 {
			return Command{}, errors.New("admin pepper-usage takes no arguments")
		}
		return Command{Admin: &AdminCommand{Action: AdminPepperUsage}}, nil
	case AdminBootstrap:
		fs := flag.NewFlagSet("admin bootstrap", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		tenant := fs.String("tenant-name", "", "name of the tenant to create")
		client := fs.String("client-name", "", "name of the client to create")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return Command{}, ErrHelp
			}
			return Command{}, err
		}
		if fs.NArg() > 0 {
			return Command{}, fmt.Errorf("unexpected argument %q", sanitize(strings.Join(fs.Args(), " ")))
		}
		if *tenant == "" || *client == "" {
			return Command{}, errors.New("admin bootstrap requires --tenant-name and --client-name")
		}
		return Command{Admin: &AdminCommand{Action: AdminBootstrap, TenantName: *tenant, ClientName: *client}}, nil
	default:
		return Command{}, fmt.Errorf("unknown admin subcommand %q (valid: bootstrap, pepper-usage)", sanitize(args[0]))
	}
}
