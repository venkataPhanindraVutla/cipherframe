package db

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// TokenHash returns the SHA-256 of a playback token's exact text. Key fetches are counted under it,
// so the token itself is never stored.
func TokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// BumpPlaybackKeyWindow counts one key request in the session's fixed one-minute window and returns
// the window's start and the count including this request. A window that is unset or at least a
// minute old restarts at now. It returns not_found for an unknown session.
func (r *Repos) BumpPlaybackKeyWindow(ctx context.Context, tenantID id.TenantID, sessionHash []byte, now time.Time) (start time.Time, count int, err error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return time.Time{}, 0, err
	}
	row, err := r.q.BumpPlaybackKeyWindow(ctx, dbgen.BumpPlaybackKeyWindowParams{Now: now, TenantID: tid, IDHash: sessionHash})
	if err != nil {
		return time.Time{}, 0, mapError(err)
	}
	if row.KeyWindowStart == nil { // cannot happen: the statement sets it
		return time.Time{}, 0, errs.New(errs.InternalError, "An internal error occurred.")
	}
	return row.KeyWindowStart.UTC(), int(row.KeyWindowCount), nil
}

// ReservePlaybackKeyFetch takes one of the token's key fetches, atomically: ok is false, and
// nothing changes, when the token has already used limit. expires is the token's expiry, kept so the
// row can be swept afterwards. A caller that then fails to produce a key gives the fetch back with
// ReleasePlaybackKeyFetch.
func (r *Repos) ReservePlaybackKeyFetch(ctx context.Context, tokenHash, sessionHash []byte, expires time.Time, limit int) (ok bool, err error) {
	if len(tokenHash) != sha256.Size || len(sessionHash) != sha256.Size || limit < 1 {
		return false, errs.New(errs.InvalidRequest, "invalid key fetch")
	}
	_, err = r.q.ReservePlaybackKeyFetch(ctx, dbgen.ReservePlaybackKeyFetchParams{
		TokenHash: tokenHash, SessionHash: sessionHash, ExpiresAt: expires, MaxFetches: int32(limit), //nolint:gosec // max is validated to 1..1000 by the settings
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, mapError(err)
	}
	return true, nil
}

// ReleasePlaybackKeyFetch gives back a fetch taken by ReservePlaybackKeyFetch.
func (r *Repos) ReleasePlaybackKeyFetch(ctx context.Context, tokenHash []byte) error {
	return mapError(r.q.ReleasePlaybackKeyFetch(ctx, tokenHash))
}

// MarkKeyReplay marks a token that is over its bound, once: it returns the token's session hash
// and true for the call that set the mark, and false for every later call for the same token. The
// anomaly event itself is raised by package anomaly.
func (r *Repos) MarkKeyReplay(ctx context.Context, tokenHash []byte, now time.Time) (sessionHash []byte, first bool, err error) {
	h, err := r.q.MarkKeyReplay(ctx, dbgen.MarkKeyReplayParams{Now: now, TokenHash: tokenHash})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, mapError(err)
	}
	return h, true, nil
}

// MarkPlaybackKeyServed records that the session has been served the content key. Only the first
// call changes the row.
func (r *Repos) MarkPlaybackKeyServed(ctx context.Context, tenantID id.TenantID, sessionHash []byte, now time.Time) error {
	tid, err := requirePG(tenantID)
	if err != nil {
		return err
	}
	return mapError(r.q.MarkPlaybackKeyServed(ctx, dbgen.MarkPlaybackKeyServedParams{Now: now, TenantID: tid, IDHash: sessionHash}))
}

// SweepPlaybackKeyFetches deletes the key-fetch counters of tokens that expired before the given
// time, and returns how many it deleted.
func (r *Repos) SweepPlaybackKeyFetches(ctx context.Context, before time.Time) (int64, error) {
	n, err := r.q.SweepPlaybackKeyFetches(ctx, before)
	return n, mapError(err)
}
