package db

import (
	"context"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
)

// SigningKey is a row of signing_keys (ADR 0033). PrivateEnvelope is the KMS-wrapped seed and is
// empty on rows read by ListSigningKeys, which never selects it. The envelope is ciphertext, but it
// is still not placed in logs or responses.
type SigningKey struct {
	KeyID           string
	Purpose         string
	Algorithm       string
	PublicKey       []byte
	PrivateEnvelope []byte
	State           string
	IsCurrent       bool
	CreatedAt       time.Time
	ActivatedAt     time.Time
	RetiredAt       *time.Time
}

// NewSigningKey is the input for InsertSigningKey. The key becomes the current signer.
type NewSigningKey struct {
	KeyID           string
	Purpose         string
	Algorithm       string
	PublicKey       []byte
	PrivateEnvelope []byte
	At              time.Time
}

const signingKeysLock = "cipherframe.signing_keys"

func signingKeyFromRow(r dbgen.SigningKey) SigningKey {
	return SigningKey{
		KeyID: r.KeyID, Purpose: r.Purpose, Algorithm: r.Algorithm, PublicKey: r.PublicKey,
		PrivateEnvelope: r.PrivateEnvelope, State: r.State, IsCurrent: r.IsCurrent,
		CreatedAt: r.CreatedAt.UTC(), ActivatedAt: r.ActivatedAt.UTC(), RetiredAt: utcPtr(r.RetiredAt),
	}
}

// LockSigningKeys takes a transaction-scoped advisory lock that serialises every change of the
// signing key set. Call it first in the transaction.
func (r *Repos) LockSigningKeys(ctx context.Context) error {
	return mapError(r.q.LockSigningKeys(ctx, signingKeysLock))
}

// ListSigningKeys returns every key of the purpose, oldest first, without the wrapped private key.
func (r *Repos) ListSigningKeys(ctx context.Context, purpose string) ([]SigningKey, error) {
	rows, err := r.q.ListSigningKeys(ctx, purpose)
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]SigningKey, len(rows))
	for i, row := range rows {
		out[i] = SigningKey{
			KeyID: row.KeyID, Purpose: row.Purpose, Algorithm: row.Algorithm, PublicKey: row.PublicKey,
			State: row.State, IsCurrent: row.IsCurrent,
			CreatedAt: row.CreatedAt.UTC(), ActivatedAt: row.ActivatedAt.UTC(), RetiredAt: utcPtr(row.RetiredAt),
		}
	}
	return out, nil
}

// GetCurrentSigningKey returns the current signer with its wrapped private key, or not_found when
// the purpose has no key yet.
func (r *Repos) GetCurrentSigningKey(ctx context.Context, purpose string) (SigningKey, error) {
	row, err := r.q.GetCurrentSigningKey(ctx, purpose)
	if err != nil {
		return SigningKey{}, mapError(err)
	}
	return signingKeyFromRow(row), nil
}

// GetSigningKey returns a key with its wrapped private key, or not_found.
func (r *Repos) GetSigningKey(ctx context.Context, keyID string) (SigningKey, error) {
	row, err := r.q.GetSigningKey(ctx, keyID)
	if err != nil {
		return SigningKey{}, mapError(err)
	}
	return signingKeyFromRow(row), nil
}

// CountSigningKeys returns how many keys the purpose has.
func (r *Repos) CountSigningKeys(ctx context.Context, purpose string) (int, error) {
	n, err := r.q.CountSigningKeys(ctx, purpose)
	return int(n), mapError(err)
}

// InsertSigningKey demotes the current signer of the purpose (it stays active and published) and
// inserts the new key as the current signer. Call it under LockSigningKeys, in one transaction.
func (r *Repos) InsertSigningKey(ctx context.Context, in NewSigningKey) (SigningKey, error) {
	if err := r.q.ClearCurrentSigningKey(ctx, in.Purpose); err != nil {
		return SigningKey{}, mapError(err)
	}
	row, err := r.q.InsertSigningKey(ctx, dbgen.InsertSigningKeyParams{
		KeyID: in.KeyID, Purpose: in.Purpose, Algorithm: in.Algorithm, PublicKey: in.PublicKey,
		PrivateEnvelope: in.PrivateEnvelope, At: in.At,
	})
	if err != nil {
		return SigningKey{}, mapError(err)
	}
	return signingKeyFromRow(row), nil
}

// RetireSigningKey marks an active, non-current key retired. It returns not_found when no such key
// matches (the caller distinguishes the reasons under the lock).
func (r *Repos) RetireSigningKey(ctx context.Context, keyID string, at time.Time) (SigningKey, error) {
	row, err := r.q.RetireSigningKey(ctx, dbgen.RetireSigningKeyParams{KeyID: keyID, At: at})
	if err != nil {
		return SigningKey{}, mapError(err)
	}
	return signingKeyFromRow(row), nil
}
