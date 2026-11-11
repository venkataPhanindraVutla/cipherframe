package db

import (
	"context"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// Repos is the set of repositories over one connection source: a pool, or a transaction inside
// Tx. All methods return *errs.Error values (see mapError).
type Repos struct {
	q *dbgen.Queries
	// conn is the same connection source as q, for the few statements sqlc cannot generate.
	conn dbgen.DBTX
}

// New returns repositories over db, which is a *pgxpool.Pool, *pgx.Conn or pgx.Tx.
func New(db dbgen.DBTX) *Repos { return &Repos{q: dbgen.New(db), conn: db} }

// Beginner starts transactions. *pgxpool.Pool implements it.
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Tx runs fn in a transaction and commits if fn returns nil. If fn returns an error or panics,
// the transaction is rolled back. fn's error is returned unchanged.
func Tx(ctx context.Context, b Beginner, fn func(*Repos) error) (err error) {
	tx, err := b.Begin(ctx)
	if err != nil {
		return mapError(err)
	}
	committed := false
	defer func() {
		if !committed {
			// The caller's context may already be cancelled; the rollback must still happen.
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	if err := fn(New(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError(err)
	}
	committed = true
	return nil
}

// CreateTenant inserts a tenant with a new ID.
func (r *Repos) CreateTenant(ctx context.Context, name string) (Tenant, error) {
	row, err := r.q.CreateTenant(ctx, dbgen.CreateTenantParams{ID: toPG(id.New[id.TenantKind]()), Name: name})
	if err != nil {
		return Tenant{}, mapError(err)
	}
	return tenantFromRow(row), nil
}

// GetTenant returns the tenant, or not_found.
func (r *Repos) GetTenant(ctx context.Context, tenantID id.TenantID) (Tenant, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return Tenant{}, err
	}
	row, err := r.q.GetTenant(ctx, tid)
	if err != nil {
		return Tenant{}, mapError(err)
	}
	return tenantFromRow(row), nil
}

// CreateClient inserts a client under tenantID with a new ID.
func (r *Repos) CreateClient(ctx context.Context, tenantID id.TenantID, name string) (Client, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return Client{}, err
	}
	row, err := r.q.CreateClient(ctx, dbgen.CreateClientParams{
		ID: toPG(id.New[id.ClientKind]()), TenantID: tid, Name: name,
	})
	if err != nil {
		return Client{}, mapError(err)
	}
	return clientFromRow(row), nil
}

// GetClient returns the client if it belongs to tenantID, or not_found.
func (r *Repos) GetClient(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (Client, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return Client{}, err
	}
	cid, err := requirePG(clientID)
	if err != nil {
		return Client{}, err
	}
	row, err := r.q.GetClient(ctx, dbgen.GetClientParams{TenantID: tid, ID: cid})
	if err != nil {
		return Client{}, mapError(err)
	}
	return clientFromRow(row), nil
}

// ListClients returns the tenant's clients, oldest first.
func (r *Repos) ListClients(ctx context.Context, tenantID id.TenantID, limit, offset int) ([]Client, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, err
	}
	if limit < 1 || offset < 0 || limit > maxPage {
		return nil, errs.New(errs.InvalidRequest, "invalid page size or offset")
	}
	rows, err := r.q.ListClientsByTenant(ctx, dbgen.ListClientsByTenantParams{
		TenantID: tid, Limit: int32(limit), Offset: int32(offset), //nolint:gosec // bounded by maxPage
	})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]Client, len(rows))
	for i, row := range rows {
		out[i] = clientFromRow(row)
	}
	return out, nil
}

// maxPage bounds every list query.
const maxPage = 1000

// CreateAPIKey inserts a key with a new ID. A duplicate prefix returns conflict. Scopes are
// validated here as well as by the database.
func (r *Repos) CreateAPIKey(ctx context.Context, in NewAPIKey) (APIKey, error) {
	cid, err := requirePG(in.ClientID)
	if err != nil {
		return APIKey{}, err
	}
	for _, s := range in.Scopes {
		if !s.Valid() {
			return APIKey{}, errs.New(errs.InvalidRequest, "unknown scope")
		}
	}
	row, err := r.q.CreateAPIKey(ctx, dbgen.CreateAPIKeyParams{
		ID:            toPG(id.New[id.APIKeyKind]()),
		ClientID:      cid,
		Name:          in.Name,
		Prefix:        in.Prefix,
		SecretHash:    in.SecretHash,
		PepperVersion: int32(in.PepperVersion), //nolint:gosec // pepper versions are small
		Scopes:        scopesToStrings(in.Scopes),
	})
	if err != nil {
		return APIKey{}, mapError(err)
	}
	return apiKeyFromRow(row), nil
}

// GetAPIKey returns the key if its client belongs to tenantID (revoked keys included), or
// not_found.
func (r *Repos) GetAPIKey(ctx context.Context, tenantID id.TenantID, keyID id.APIKeyID) (APIKey, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return APIKey{}, err
	}
	kid, err := requirePG(keyID)
	if err != nil {
		return APIKey{}, err
	}
	row, err := r.q.GetAPIKey(ctx, dbgen.GetAPIKeyParams{TenantID: tid, ID: kid})
	if err != nil {
		return APIKey{}, mapError(err)
	}
	return apiKeyFromRow(row), nil
}

// GetActiveAPIKeyByPrefix is the authentication lookup. Revoked keys are never returned
// (not_found). The result carries disabled markers for the client and tenant; the caller must
// fail closed when either is set.
func (r *Repos) GetActiveAPIKeyByPrefix(ctx context.Context, prefix string) (AuthKey, error) {
	row, err := r.q.GetActiveAPIKeyByPrefix(ctx, prefix)
	if err != nil {
		return AuthKey{}, mapError(err)
	}
	return authKeyFromRow(row), nil
}

// RotateAPIKey replaces the secret on the same row: the current hash becomes the previous hash,
// valid until p.PreviousValidUntil. Id, prefix, client and scopes do not change. A revoked key
// or a key of another tenant returns not_found.
func (r *Repos) RotateAPIKey(ctx context.Context, tenantID id.TenantID, keyID id.APIKeyID, p RotateParams) (APIKey, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return APIKey{}, err
	}
	kid, err := requirePG(keyID)
	if err != nil {
		return APIKey{}, err
	}
	if len(p.NewSecretHash) == 0 || p.PreviousValidUntil.Before(p.RotatedAt) {
		return APIKey{}, errs.New(errs.InvalidRequest, "invalid rotation parameters")
	}
	row, err := r.q.RotateAPIKey(ctx, dbgen.RotateAPIKeyParams{
		PreviousValidUntil: p.PreviousValidUntil,
		NewSecretHash:      p.NewSecretHash,
		NewPepperVersion:   int32(p.NewPepperVersion), //nolint:gosec // pepper versions are small
		RotatedAt:          p.RotatedAt,
		ID:                 kid,
		TenantID:           tid,
	})
	if err != nil {
		return APIKey{}, mapError(err)
	}
	return apiKeyFromRow(row), nil
}

// RevokeAPIKey disables the key immediately. It is idempotent: a key already revoked keeps its
// original time. A key of another tenant returns not_found.
func (r *Repos) RevokeAPIKey(ctx context.Context, tenantID id.TenantID, keyID id.APIKeyID, at time.Time) (APIKey, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return APIKey{}, err
	}
	kid, err := requirePG(keyID)
	if err != nil {
		return APIKey{}, err
	}
	row, err := r.q.RevokeAPIKey(ctx, dbgen.RevokeAPIKeyParams{RevokedAt: at, ID: kid, TenantID: tid})
	if err != nil {
		return APIKey{}, mapError(err)
	}
	return apiKeyFromRow(row), nil
}

// TouchAPIKeyLastUsed records that the key authenticated a request. It is not tenant-scoped
// because it runs on the authentication path, after the prefix lookup.
func (r *Repos) TouchAPIKeyLastUsed(ctx context.Context, keyID id.APIKeyID, at time.Time) error {
	kid, err := requirePG(keyID)
	if err != nil {
		return err
	}
	return mapError(r.q.TouchAPIKeyLastUsed(ctx, dbgen.TouchAPIKeyLastUsedParams{ID: kid, LastUsedAt: at}))
}

// CountAPIKeysByPepperVersion returns, per pepper version, how many non-revoked keys still
// reference it: by their current hash, or by a previous hash still valid at now (ADR 0016).
func (r *Repos) CountAPIKeysByPepperVersion(ctx context.Context, now time.Time) (map[int]int64, error) {
	rows, err := r.q.CountAPIKeysByPepperVersion(ctx, now)
	if err != nil {
		return nil, mapError(err)
	}
	out := make(map[int]int64, len(rows))
	for _, row := range rows {
		out[int(row.PepperVersion)] = row.KeyCount
	}
	return out, nil
}

// CreateAsset inserts an asset with a new ID, created by clientID. The client must belong to
// tenantID, otherwise not_found is returned and nothing is written.
func (r *Repos) CreateAsset(ctx context.Context, tenantID id.TenantID, clientID id.ClientID, state AssetState) (Asset, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return Asset{}, err
	}
	cid, err := requirePG(clientID)
	if err != nil {
		return Asset{}, err
	}
	if !state.Valid() {
		return Asset{}, errs.New(errs.InvalidRequest, "unknown asset state")
	}
	row, err := r.q.CreateAsset(ctx, dbgen.CreateAssetParams{
		ID: toPG(id.New[id.AssetKind]()), State: string(state), ClientID: cid, TenantID: tid,
	})
	if err != nil {
		return Asset{}, mapError(err)
	}
	return assetFromRow(row), nil
}

// GetAsset returns the asset if it belongs to tenantID; another tenant's asset is not_found.
func (r *Repos) GetAsset(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) (Asset, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return Asset{}, err
	}
	aid, err := requirePG(assetID)
	if err != nil {
		return Asset{}, err
	}
	row, err := r.q.GetAsset(ctx, dbgen.GetAssetParams{TenantID: tid, ID: aid})
	if err != nil {
		return Asset{}, mapError(err)
	}
	return assetFromRow(row), nil
}

// InsertAuditEvent appends an audit event with a new UUIDv7 ID.
func (r *Repos) InsertAuditEvent(ctx context.Context, in NewAuditEvent) (AuditEvent, error) {
	tid, err := requirePG(in.TenantID)
	if err != nil {
		return AuditEvent{}, err
	}
	if in.Action == "" {
		return AuditEvent{}, errs.New(errs.InvalidRequest, "audit action is required")
	}
	row, err := r.q.InsertAuditEvent(ctx, dbgen.InsertAuditEventParams{
		ID:        rawToPG(uuid.NewV7()),
		TenantID:  tid,
		ClientID:  toPG(in.ClientID),
		ApiKeyID:  toPG(in.APIKeyID),
		Action:    in.Action,
		Target:    strPtr(in.Target),
		RequestID: strPtr(in.RequestID),
	})
	if err != nil {
		return AuditEvent{}, mapError(err)
	}
	return auditFromRow(row), nil
}

// ListAuditEvents returns up to limit of the tenant's events, oldest first, starting after
// after (nil for the beginning).
func (r *Repos) ListAuditEvents(ctx context.Context, tenantID id.TenantID, after *AuditCursor, limit int) ([]AuditEvent, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > maxPage {
		return nil, errs.New(errs.InvalidRequest, "invalid page size")
	}
	p := dbgen.ListAuditEventsByTenantParams{TenantID: tid, MaxRows: int32(limit)} //nolint:gosec // bounded by maxPage
	if after != nil {
		t := after.CreatedAt
		p.AfterID = rawToPG(after.ID)
		p.AfterCreatedAt = &t
	}
	rows, err := r.q.ListAuditEventsByTenant(ctx, p)
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]AuditEvent, len(rows))
	for i, row := range rows {
		out[i] = auditFromRow(row)
	}
	return out, nil
}
