package signing

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// Prepare returns a Signer for code that signs inside a database transaction. A *Manager reads the
// current key from the database on every Sign, so signing inside a transaction needs a second pool
// connection while the transaction holds one (and its row locks). With a small pool and requests
// queued behind those locks, each holding a connection, that deadlocks. The returned Signer holds
// the current key in memory and signs without the database; release clears the key. Call Prepare
// before the transaction starts. Any other Signer is returned as it is.
func Prepare(ctx context.Context, s Signer) (Signer, func(), error) {
	m, ok := s.(*Manager)
	if !ok {
		return s, func() {}, nil
	}
	row, err := m.repos.GetCurrentSigningKey(ctx, PurposeIntegrity)
	if err != nil {
		if isNotFound(err) {
			return nil, nil, errs.Wrap(errs.InternalError, "internal error", errors.New("signing: no current signing key"))
		}
		return nil, nil, err
	}
	priv, err := m.open(ctx, row)
	if err != nil {
		return nil, nil, err
	}
	p := &prepared{m: m, keyID: row.KeyID, priv: priv}
	return p, p.release, nil
}

// prepared signs with one key held in memory.
type prepared struct {
	m     *Manager
	keyID string
	priv  ed25519.PrivateKey
}

func (p *prepared) Sign(_ context.Context, message []byte) (string, []byte, error) {
	if len(p.priv) != ed25519.PrivateKeySize { // released
		return "", nil, errs.New(errs.InternalError, "internal error")
	}
	return p.keyID, ed25519.Sign(p.priv, message), nil
}

func (p *prepared) PublicKeys(ctx context.Context) ([]PublicKey, error) { return p.m.PublicKeys(ctx) }

func (p *prepared) release() {
	clear(p.priv)
	p.priv = nil
}
