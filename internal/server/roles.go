// Package server assembles and runs the roles of the cipherframe-server binary (ADR 0008): it
// parses --role, connects the dependencies, builds the api and edge listeners and the worker
// loop, and shuts them down gracefully.
package server

import (
	"errors"
	"fmt"
	"strings"
)

// Role is one server role.
type Role string

// The roles of ADR 0008.
const (
	RoleAPI    Role = "api"
	RoleEdge   Role = "edge"
	RoleWorker Role = "worker"
)

// ParseRoles parses the --role flag: a comma-separated list of api, edge and worker. The value is
// required; unknown names, duplicates and empty entries are rejected. Order is preserved.
func ParseRoles(s string) ([]Role, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("--role is required: a comma-separated list of api, edge, worker")
	}
	seen := map[Role]bool{}
	var roles []Role
	for _, part := range strings.Split(s, ",") {
		r := Role(strings.TrimSpace(part))
		switch r {
		case RoleAPI, RoleEdge, RoleWorker:
		case "":
			return nil, errors.New("--role has an empty entry")
		default:
			return nil, fmt.Errorf("--role: unknown role %q (valid: api, edge, worker)", sanitize(string(r)))
		}
		if seen[r] {
			return nil, fmt.Errorf("--role: duplicate role %q", r)
		}
		seen[r] = true
		roles = append(roles, r)
	}
	return roles, nil
}

// Has reports whether roles contains r.
func Has(roles []Role, r Role) bool {
	for _, x := range roles {
		if x == r {
			return true
		}
	}
	return false
}

// sanitize keeps a user-supplied word short and printable before it goes into an error message.
func sanitize(s string) string {
	if len(s) > 32 {
		s = s[:32]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
