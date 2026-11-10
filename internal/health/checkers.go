package health

import (
	"context"
	"errors"

	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
)

// Pinger is the part of a database pool the database check needs. *pgxpool.Pool satisfies it.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Database returns a checker named "database" that pings p.
func Database(p Pinger) Checker {
	return Func("database", p.Ping)
}

// ProbeKey is the fixed object key the storage check asks about. It sits under a reserved prefix
// that the key layout (internal/storage/keys) never produces, and nothing ever writes it.
const ProbeKey = "_cipherframe/readiness-probe"

// Storage returns a checker named name that proves the store is reachable and the credentials
// are accepted, by asking for ProbeKey. "Not found" is the expected answer and counts as
// reachable. A refused credential, a timeout and any other failure count as not ready.
func Storage(name string, s storage.Store) Checker {
	return Func(name, func(ctx context.Context) error {
		_, err := s.Head(ctx, ProbeKey)
		if err == nil || errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return err
	})
}
