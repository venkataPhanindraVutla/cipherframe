package contentkey

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

// Re-wrap batch sizes. A job's batch size is its argument; zero means DefaultRewrapBatch.
const (
	DefaultRewrapBatch = 100
	// MaxRewrapBatch bounds one batch (and so one transaction and one job run).
	MaxRewrapBatch = 1000
)

// RewrapResult reports one Rewrap call.
type RewrapResult struct {
	// Rewrapped is how many rows were moved to the current KEK by this call.
	Rewrapped int
	// Remaining is how many rows were still on another KEK when the call committed. It is only
	// meaningful when Rewrap returned no error.
	Remaining int64
}

// Rewrap moves one batch of content keys from their recorded KEK to the current provider's current
// KEK (ADR 0020). For each row it unwraps with the provider that wrapped it, using the associated
// data of the row's recorded binding, wraps the same 16 key bytes with the current provider using
// the associated data of the NEW binding, checks that the new ciphertext unwraps to the same bytes,
// and only then stores it. The content key itself never changes, so no media is re-encrypted.
//
// The stored update is guarded: it applies only while the row still names the KEK that was read,
// so concurrent re-wraps cannot overwrite each other. Rewrap is idempotent: a row already on the
// current KEK is never selected.
//
// All updates of the batch commit in one transaction. After the last update, and in the same
// transaction, onMore is called when keys remain on another KEK; it enqueues the next run, so a
// crash between batches resumes cleanly and a rolled-back batch enqueues nothing. onMore may be nil.
//
// Failure is closed: when the key service is unavailable the error is dependency_unavailable
// (retryable); a key that fails authentication is internal_error and is logged with identifiers
// only. On the first failure the rows already re-wrapped in this call are committed and the rest
// are left untouched, and onMore is not called.
func (m *Manager) Rewrap(ctx context.Context, batch int, onMore func(ctx context.Context, tx pgx.Tx, remaining int64) error) (RewrapResult, error) {
	if m.begin == nil {
		return RewrapResult{}, errs.Wrap(errs.InternalError, "internal error", errors.New("contentkey: the pool cannot start transactions"))
	}
	if batch == 0 {
		batch = DefaultRewrapBatch
	}
	if batch < 1 || batch > MaxRewrapBatch {
		return RewrapResult{}, errs.New(errs.InvalidRequest, "the batch size is out of range")
	}

	p := m.reg.Current()
	ref, err := p.Current(ctx)
	if err != nil {
		return RewrapResult{}, kms.ToAppError(err)
	}
	target := db.KEKRef{Provider: p.Name(), KeyID: ref.KeyID, Version: ref.Version}
	rows, err := m.repos.ListContentKeysNotOnKEK(ctx, target, id.ContentKeyID{}, batch)
	if err != nil {
		return RewrapResult{}, err
	}

	// Provider calls happen outside the transaction, so no database transaction is held open
	// across network calls to the key service.
	var (
		updates []db.RewrapUpdate
		failure error
	)
	for _, row := range rows {
		u, err := m.rewrapRow(ctx, row)
		if err != nil {
			failure = err
			break
		}
		updates = append(updates, u)
	}

	res, err := m.applyRewrap(ctx, target, updates, failure == nil, onMore)
	if failure != nil {
		if err != nil {
			m.log.ErrorContext(ctx, "content key re-wrap could not store a partial batch")
		}
		m.log.WarnContext(ctx, "content key re-wrap stopped",
			slog.Int("rewrapped", res.Rewrapped), slog.String("code", string(codeOf(failure))))
		return res, failure
	}
	if err != nil {
		return res, err
	}
	if res.Rewrapped == 0 && len(rows) > 0 {
		// Every row changed under us. Another run is making progress; retry rather than spin.
		return res, errs.Wrap(errs.InternalError, "internal error", errors.New("contentkey: rows changed during re-wrap"))
	}
	m.log.InfoContext(ctx, "content keys re-wrapped",
		slog.Int("rewrapped", res.Rewrapped), slog.Int64("remaining", res.Remaining),
		slog.String("provider", target.Provider), slog.String("kek_version", target.Version))
	return res, nil
}

// applyRewrap stores updates in one transaction. When last is true and keys remain, it calls onMore
// before committing.
func (m *Manager) applyRewrap(ctx context.Context, target db.KEKRef, updates []db.RewrapUpdate, last bool, onMore func(context.Context, pgx.Tx, int64) error) (RewrapResult, error) {
	var res RewrapResult
	if len(updates) == 0 && !last {
		return res, nil
	}
	tx, err := m.begin.Begin(ctx)
	if err != nil {
		return res, db.MapError(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	repos := db.New(tx)
	applied := 0
	for _, u := range updates {
		ok, err := repos.UpdateContentKeyWrapped(ctx, u)
		if err != nil {
			return res, err
		}
		if ok {
			applied++
		}
	}
	remaining, err := repos.CountContentKeysNotOnKEK(ctx, target)
	if err != nil {
		return res, err
	}
	if last && remaining > 0 && applied > 0 && onMore != nil {
		if err := onMore(ctx, tx, remaining); err != nil {
			return res, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return res, db.MapError(err)
	}
	committed = true
	return RewrapResult{Rewrapped: applied, Remaining: remaining}, nil
}

// rewrapRow computes the update for one row without touching the database.
func (m *Manager) rewrapRow(ctx context.Context, row db.ContentKeyRow) (db.RewrapUpdate, error) {
	if row.EnvelopeVersion != EnvelopeVersion {
		m.log.ErrorContext(ctx, "content key has an unsupported envelope version",
			slog.String("content_key_id", row.ID.String()), slog.Int("envelope_version", row.EnvelopeVersion))
		return db.RewrapUpdate{}, kms.ToAppError(kms.New(kms.Other, row.KEK.Provider, "unwrap", "unsupported envelope version"))
	}
	oldAAD := AAD(Binding{
		EnvelopeVersion: row.EnvelopeVersion, AssetID: row.AssetID, ContentKeyID: row.ID,
		Provider: row.KEK.Provider, KEKKeyID: row.KEK.KeyID, KEKVersion: row.KEK.Version,
	})
	plain, err := m.reg.Unwrap(ctx, kms.Wrapped{
		Provider: row.KEK.Provider, KeyID: row.KEK.KeyID, Version: row.KEK.Version, Ciphertext: row.Wrapped,
	}, oldAAD)
	if err != nil {
		m.logUnwrapFailure(ctx, row, err)
		return db.RewrapUpdate{}, kms.ToAppError(err)
	}
	defer clear(plain)
	if len(plain) != KeyBytes {
		err := kms.New(kms.Invalid, row.KEK.Provider, "unwrap", "unwrapped key has the wrong length")
		m.logUnwrapFailure(ctx, row, err)
		return db.RewrapUpdate{}, kms.ToAppError(err)
	}

	// The new wrap binds the NEW provider, KEK id and KEK version; the old ciphertext is not valid
	// under it, and the new one is not valid under the old binding.
	w, err := m.wrap(ctx, plain, row.AssetID, row.ID)
	if err != nil {
		return db.RewrapUpdate{}, err
	}
	next := db.KEKRef{Provider: w.Provider, KeyID: w.KeyID, Version: w.Version}

	// Verify before the old ciphertext is replaced: a wrap that does not read back must never
	// destroy the only copy of a key.
	failed := row
	failed.KEK = next
	check, err := m.reg.Unwrap(ctx, w, AAD(Binding{
		EnvelopeVersion: EnvelopeVersion, AssetID: row.AssetID, ContentKeyID: row.ID,
		Provider: next.Provider, KEKKeyID: next.KeyID, KEKVersion: next.Version,
	}))
	if err != nil {
		m.logUnwrapFailure(ctx, failed, err)
		return db.RewrapUpdate{}, kms.ToAppError(err)
	}
	defer clear(check)
	if subtle.ConstantTimeCompare(check, plain) != 1 {
		err := kms.New(kms.Invalid, next.Provider, "unwrap", "re-wrapped key does not read back")
		m.logUnwrapFailure(ctx, failed, err)
		return db.RewrapUpdate{}, kms.ToAppError(err)
	}

	return db.RewrapUpdate{
		ID: row.ID, From: row.KEK, To: next, EnvelopeVersion: EnvelopeVersion, Wrapped: w.Ciphertext,
	}, nil
}

// codeOf returns the error code of err for logging: the code only, never its text.
func codeOf(err error) errs.Code {
	var e *errs.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return errs.InternalError
}
