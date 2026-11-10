package auth

import (
	"context"
	"errors"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// Audit actions written by Manager (the audit_events.action column).
const (
	AuditTenantCreate = "tenant.create"
	AuditClientCreate = "client.create"
	AuditKeyCreate    = "key.create"
	AuditKeyRotate    = "key.rotate"
	AuditKeyRevoke    = "key.revoke"
)

// Limits.
const (
	MaxNameRunes = 100
	// DefaultOverlap is how long the previous secret keeps working after a rotation (ADR 0018).
	DefaultOverlap = 10 * time.Minute
	// MaxOverlap is the longest allowed overlap.
	MaxOverlap = 24 * time.Hour
	// prefixAttempts is how often key creation retries after a prefix collision.
	prefixAttempts = 5
)

// Pool is the database handle Manager needs: queries and transactions. *pgxpool.Pool implements
// it.
type Pool interface {
	dbgen.DBTX
	db.Beginner
}

// Actor is who performed a management operation, for the audit row. The zero value is used by
// the bootstrap command, which has no caller.
type Actor struct {
	ClientID  id.ClientID
	KeyID     id.APIKeyID
	RequestID string
}

// Issued is a key row together with its full key. The full key is returned to the caller once and
// is never stored.
type Issued struct {
	Key    db.APIKey
	Secret Key
}

// Manager creates clients and keys, and rotates and revokes keys. Every method is scoped to a
// tenant and writes its audit row in the same transaction as the change.
type Manager struct {
	pool    Pool
	repos   *db.Repos
	peppers Peppers
	now     func() time.Time
}

// NewManager returns a Manager. now defaults to time.Now.
func NewManager(pool Pool, peppers Peppers, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{pool: pool, repos: db.New(pool), peppers: peppers, now: now}
}

// ValidateName checks a client or key name: 1 to 100 characters, not only whitespace, no control
// characters. The error is an invalid_request.
func ValidateName(s string) error {
	n := utf8.RuneCountInString(s)
	if !utf8.ValidString(s) || n < 1 || n > MaxNameRunes {
		return errs.New(errs.InvalidRequest, "name must be 1 to 100 characters")
	}
	blank := true
	for _, r := range s {
		if unicode.IsControl(r) {
			return errs.New(errs.InvalidRequest, "name must not contain control characters")
		}
		if !unicode.IsSpace(r) {
			blank = false
		}
	}
	if blank {
		return errs.New(errs.InvalidRequest, "name must not be blank")
	}
	return nil
}

// ResolveScopes validates requested scopes. A nil slice means "not given" and yields the default
// scopes; an empty or duplicated list, or an unknown scope, is an invalid_request.
func ResolveScopes(in []db.Scope) ([]db.Scope, error) {
	if in == nil {
		return DefaultScopes(), nil
	}
	if len(in) == 0 {
		return nil, errs.New(errs.InvalidRequest, "scopes must not be empty")
	}
	seen := map[db.Scope]bool{}
	for _, s := range in {
		if !s.Valid() {
			return nil, errs.New(errs.InvalidRequest, "unknown scope")
		}
		if seen[s] {
			return nil, errs.New(errs.InvalidRequest, "duplicate scope")
		}
		seen[s] = true
	}
	return slices.Clone(in), nil
}

func isConflict(err error) bool {
	var e *errs.Error
	return errors.As(err, &e) && e.Code == errs.Conflict
}

// currentPepper returns the version and bytes used for new hashes.
func (m *Manager) currentPepper() (int, []byte, error) {
	v, p := m.peppers.Current()
	if v < 1 || p.IsEmpty() {
		return 0, nil, errs.New(errs.InternalError, "An internal error occurred.")
	}
	return v, []byte(p.Reveal()), nil
}

func (m *Manager) audit(ctx context.Context, r *db.Repos, tenant id.TenantID, a Actor, action, target string) error {
	_, err := r.InsertAuditEvent(ctx, db.NewAuditEvent{
		TenantID: tenant, ClientID: a.ClientID, APIKeyID: a.KeyID,
		Action: action, Target: target, RequestID: a.RequestID,
	})
	return err
}

// CreateClient creates a client in the tenant.
func (m *Manager) CreateClient(ctx context.Context, tenant id.TenantID, a Actor, name string) (db.Client, error) {
	if err := ValidateName(name); err != nil {
		return db.Client{}, err
	}
	var out db.Client
	err := db.Tx(ctx, m.pool, func(r *db.Repos) error {
		c, err := r.CreateClient(ctx, tenant, name)
		if err != nil {
			return err
		}
		out = c
		return m.audit(ctx, r, tenant, a, AuditClientCreate, c.ID.String())
	})
	return out, err
}

// ListClients returns up to limit clients after the cursor (the zero ID for the first page) and
// the cursor of the next page, which is the zero ID on the last page.
func (m *Manager) ListClients(ctx context.Context, tenant id.TenantID, after id.ClientID, limit int) ([]db.Client, id.ClientID, error) {
	rows, err := m.repos.ListClientsPage(ctx, tenant, after, limit+1)
	if err != nil {
		return nil, id.ClientID{}, err
	}
	var next id.ClientID
	if len(rows) > limit {
		rows = rows[:limit]
		next = rows[limit-1].ID
	}
	return rows, next, nil
}

// ListKeys returns up to limit keys after the cursor and the next cursor. Rows contain hashes;
// callers must expose metadata only.
func (m *Manager) ListKeys(ctx context.Context, tenant id.TenantID, after id.APIKeyID, limit int) ([]db.APIKey, id.APIKeyID, error) {
	rows, err := m.repos.ListAPIKeysPage(ctx, tenant, after, limit+1)
	if err != nil {
		return nil, id.APIKeyID{}, err
	}
	var next id.APIKeyID
	if len(rows) > limit {
		rows = rows[:limit]
		next = rows[limit-1].ID
	}
	return rows, next, nil
}

// CreateKeyInput is the input of CreateKey. A nil Scopes means the default scopes.
type CreateKeyInput struct {
	ClientID id.ClientID
	Name     string
	Scopes   []db.Scope
}

// CreateKey creates a key for a client of the tenant; another tenant's client is not_found.
func (m *Manager) CreateKey(ctx context.Context, tenant id.TenantID, a Actor, in CreateKeyInput) (Issued, error) {
	if err := ValidateName(in.Name); err != nil {
		return Issued{}, err
	}
	scopes, err := ResolveScopes(in.Scopes)
	if err != nil {
		return Issued{}, err
	}
	ver, pepper, err := m.currentPepper()
	if err != nil {
		return Issued{}, err
	}
	for range prefixAttempts {
		key, err := NewKey()
		if err != nil {
			return Issued{}, errs.Wrap(errs.InternalError, "An internal error occurred.", err)
		}
		var row db.APIKey
		// A unique violation aborts the transaction, so a prefix collision retries the whole one.
		err = db.Tx(ctx, m.pool, func(r *db.Repos) error {
			if _, err := r.GetClient(ctx, tenant, in.ClientID); err != nil {
				return err
			}
			k, err := r.CreateAPIKey(ctx, db.NewAPIKey{
				ClientID: in.ClientID, Name: in.Name, Prefix: key.Prefix(),
				SecretHash: key.Hash(pepper), PepperVersion: ver, Scopes: scopes,
			})
			if err != nil {
				return err
			}
			row = k
			return m.audit(ctx, r, tenant, a, AuditKeyCreate, k.ID.String())
		})
		if isConflict(err) {
			continue
		}
		if err != nil {
			return Issued{}, err
		}
		return Issued{Key: row, Secret: key}, nil
	}
	return Issued{}, errs.New(errs.InternalError, "An internal error occurred.")
}

// RotateKey replaces the secret of a key of the tenant on the same row. The previous secret keeps
// working for overlap (0 to MaxOverlap). A revoked key, or another tenant's key, is not_found.
func (m *Manager) RotateKey(ctx context.Context, tenant id.TenantID, keyID id.APIKeyID, overlap time.Duration, a Actor) (Issued, error) {
	if overlap < 0 || overlap > MaxOverlap {
		return Issued{}, errs.New(errs.InvalidRequest, "overlap_seconds must be between 0 and 86400")
	}
	ver, pepper, err := m.currentPepper()
	if err != nil {
		return Issued{}, err
	}
	var out Issued
	err = db.Tx(ctx, m.pool, func(r *db.Repos) error {
		cur, err := r.GetAPIKey(ctx, tenant, keyID)
		if err != nil {
			return err
		}
		if cur.RevokedAt != nil {
			return errs.New(errs.NotFound, "resource not found")
		}
		key, err := WithNewSecret(cur.Prefix)
		if err != nil {
			return errs.Wrap(errs.InternalError, "An internal error occurred.", err)
		}
		now := m.now()
		row, err := r.RotateAPIKey(ctx, tenant, keyID, db.RotateParams{
			NewSecretHash: key.Hash(pepper), NewPepperVersion: ver,
			RotatedAt: now, PreviousValidUntil: now.Add(overlap),
		})
		if err != nil {
			return err
		}
		out = Issued{Key: row, Secret: key}
		return m.audit(ctx, r, tenant, a, AuditKeyRotate, row.ID.String())
	})
	if err != nil {
		return Issued{}, err
	}
	return out, nil
}

// RevokeKey disables a key of the tenant immediately. It is idempotent.
func (m *Manager) RevokeKey(ctx context.Context, tenant id.TenantID, keyID id.APIKeyID, a Actor) (db.APIKey, error) {
	var out db.APIKey
	err := db.Tx(ctx, m.pool, func(r *db.Repos) error {
		k, err := r.RevokeAPIKey(ctx, tenant, keyID, m.now())
		if err != nil {
			return err
		}
		out = k
		return m.audit(ctx, r, tenant, a, AuditKeyRevoke, k.ID.String())
	})
	return out, err
}

// BootstrapResult is what Bootstrap created.
type BootstrapResult struct {
	Tenant db.Tenant
	Client db.Client
	Key    db.APIKey
	Secret Key
}

// Bootstrap creates a tenant, a client and an admin key (every scope) in one transaction and
// writes their audit rows. It backs `cipherframe-server admin bootstrap`.
func (m *Manager) Bootstrap(ctx context.Context, tenantName, clientName string) (BootstrapResult, error) {
	if err := ValidateName(tenantName); err != nil {
		return BootstrapResult{}, err
	}
	if err := ValidateName(clientName); err != nil {
		return BootstrapResult{}, err
	}
	ver, pepper, err := m.currentPepper()
	if err != nil {
		return BootstrapResult{}, err
	}
	for range prefixAttempts {
		key, err := NewKey()
		if err != nil {
			return BootstrapResult{}, errs.Wrap(errs.InternalError, "An internal error occurred.", err)
		}
		var res BootstrapResult
		err = db.Tx(ctx, m.pool, func(r *db.Repos) error {
			t, err := r.CreateTenant(ctx, tenantName)
			if err != nil {
				return err
			}
			c, err := r.CreateClient(ctx, t.ID, clientName)
			if err != nil {
				return err
			}
			k, err := r.CreateAPIKey(ctx, db.NewAPIKey{
				ClientID: c.ID, Name: "bootstrap admin", Prefix: key.Prefix(),
				SecretHash: key.Hash(pepper), PepperVersion: ver, Scopes: AllScopes(),
			})
			if err != nil {
				return err
			}
			res = BootstrapResult{Tenant: t, Client: c, Key: k, Secret: key}
			actor := Actor{} // no caller: the operator ran the CLI
			for _, ev := range []struct{ action, target string }{
				{AuditTenantCreate, t.ID.String()},
				{AuditClientCreate, c.ID.String()},
				{AuditKeyCreate, k.ID.String()},
			} {
				if err := m.audit(ctx, r, t.ID, actor, ev.action, ev.target); err != nil {
					return err
				}
			}
			return nil
		})
		if isConflict(err) {
			continue
		}
		if err != nil {
			return BootstrapResult{}, err
		}
		return res, nil
	}
	return BootstrapResult{}, errs.New(errs.InternalError, "An internal error occurred.")
}
