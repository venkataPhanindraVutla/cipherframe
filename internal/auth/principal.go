package auth

import (
	"context"
	"slices"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// AllScopes returns every scope, in a stable order (ADR 0009).
func AllScopes() []db.Scope {
	return []db.Scope{
		db.ScopeAssetsRead, db.ScopeAssetsWrite, db.ScopeSessionsWrite, db.ScopeWebhooksManage, db.ScopeAdmin,
	}
}

// DefaultScopes returns the scopes a new key gets when none are given: every scope except admin.
func DefaultScopes() []db.Scope {
	var out []db.Scope
	for _, s := range AllScopes() {
		if s != db.ScopeAdmin {
			out = append(out, s)
		}
	}
	return out
}

// Principal is the authenticated caller: the key, the client it belongs to and that client's
// tenant. It holds no secret.
type Principal struct {
	TenantID id.TenantID
	ClientID id.ClientID
	KeyID    id.APIKeyID
	Scopes   []db.Scope
}

// HasScope reports whether the key holds s.
func (p Principal) HasScope(s db.Scope) bool { return slices.Contains(p.Scopes, s) }

type principalKey struct{}

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal stored by WithPrincipal.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
