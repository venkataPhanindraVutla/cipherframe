package db

import (
	"context"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// KEKUsage is the number of content keys wrapped under one KEK version.
type KEKUsage struct {
	KEK  KEKRef
	Keys int64
}

// ListContentKeysNotOnKEK returns up to limit rows whose KEK is not kek, in id order, starting
// after the row with ID after (the zero ID for the first page). It spans all tenants and serves
// the re-wrap job, which moves every key to the current KEK.
func (r *Repos) ListContentKeysNotOnKEK(ctx context.Context, kek KEKRef, after id.ContentKeyID, limit int) ([]ContentKeyRow, error) {
	if !kek.valid() || limit < 1 || limit > maxPage {
		return nil, errs.New(errs.InvalidRequest, "invalid page size or KEK")
	}
	rows, err := r.q.ListContentKeysNotOnKEK(ctx, dbgen.ListContentKeysNotOnKEKParams{
		Provider: kek.Provider, KekKeyID: kek.KeyID, KekVersion: kek.Version,
		AfterID: toPG(after), MaxRows: int32(limit), //nolint:gosec // bounded by maxPage
	})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]ContentKeyRow, len(rows))
	for i, row := range rows {
		out[i] = contentKeyFromRow(row)
	}
	return out, nil
}

// CountContentKeysNotOnKEK returns how many content keys are wrapped under a KEK other than kek.
func (r *Repos) CountContentKeysNotOnKEK(ctx context.Context, kek KEKRef) (int64, error) {
	if !kek.valid() {
		return 0, errs.New(errs.InvalidRequest, "invalid KEK")
	}
	n, err := r.q.CountContentKeysNotOnKEK(ctx, dbgen.CountContentKeysNotOnKEKParams{
		Provider: kek.Provider, KekKeyID: kek.KeyID, KekVersion: kek.Version,
	})
	if err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// CountContentKeysByKEK returns how many content keys each (provider, KEK id, KEK version) wraps,
// ordered by provider, KEK id and version. It holds no key material.
func (r *Repos) CountContentKeysByKEK(ctx context.Context) ([]KEKUsage, error) {
	rows, err := r.q.CountContentKeysByKEK(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]KEKUsage, len(rows))
	for i, row := range rows {
		out[i] = KEKUsage{
			KEK:  KEKRef{Provider: row.Provider, KeyID: row.KekKeyID, Version: row.KekVersion},
			Keys: row.Keys,
		}
	}
	return out, nil
}
