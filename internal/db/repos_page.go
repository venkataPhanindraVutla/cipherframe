package db

import (
	"context"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// ListClientsPage returns up to limit of the tenant's clients in creation order (UUIDv7 order),
// starting after the client with ID after (the zero ID for the first page).
func (r *Repos) ListClientsPage(ctx context.Context, tenantID id.TenantID, after id.ClientID, limit int) ([]Client, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > maxPage {
		return nil, errs.New(errs.InvalidRequest, "invalid page size")
	}
	rows, err := r.q.ListClientsPage(ctx, dbgen.ListClientsPageParams{
		TenantID: tid, AfterID: toPG(after), MaxRows: int32(limit), //nolint:gosec // bounded by maxPage
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

// ListAPIKeysPage returns up to limit of the tenant's keys (revoked ones included) in creation
// order, starting after the key with ID after (the zero ID for the first page).
func (r *Repos) ListAPIKeysPage(ctx context.Context, tenantID id.TenantID, after id.APIKeyID, limit int) ([]APIKey, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > maxPage {
		return nil, errs.New(errs.InvalidRequest, "invalid page size")
	}
	rows, err := r.q.ListAPIKeysPage(ctx, dbgen.ListAPIKeysPageParams{
		TenantID: tid, AfterID: toPG(after), MaxRows: int32(limit), //nolint:gosec // bounded by maxPage
	})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]APIKey, len(rows))
	for i, row := range rows {
		out[i] = apiKeyFromRow(row)
	}
	return out, nil
}
