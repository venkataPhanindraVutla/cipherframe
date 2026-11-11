package token

import (
	"errors"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
)

// KeyringFromConfig builds a Keyring from the configured playback-token keys.
func KeyringFromConfig(keys config.PlaybackKeys) (*Keyring, error) {
	if err := keys.Require(); err != nil {
		return nil, err
	}
	cur, _ := keys.Current()
	k, err := NewKeyring(keys.KeyMaterial(), cur)
	if err != nil {
		return nil, errors.New("token: invalid playback token keys")
	}
	return k, nil
}
