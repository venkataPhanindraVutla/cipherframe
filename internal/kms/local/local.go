// Package local is the development-only key provider (ADR 0019). It wraps content keys with
// AES-256-GCM (ADR 0020) under versioned KEKs read from configuration, and records provider, key id
// and KEK version exactly like the production providers.
//
// It holds KEKs in process memory and in configuration, which is what the production providers
// avoid. New therefore refuses to build outside the development environment, and logs a warning
// when it does build.
package local

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

const (
	// Name is the provider name recorded in every wrapped key.
	Name = "local"
	// KeyID is the KEK id recorded in every wrapped key. The local provider has one logical key
	// whose versions are the configured KEKs.
	KeyID = "local"

	// formatV1 is the first byte of every ciphertext: format version 1, then a 96-bit nonce, then
	// the AES-256-GCM sealed bytes (ciphertext and tag).
	formatV1  byte = 1
	nonceSize      = 12
	tagSize        = 16
)

// ErrProduction is returned by New when the environment is not development.
var ErrProduction = errors.New("local key provider is development-only and cannot run in production")

// Provider is the local development key provider. It is safe for concurrent use. Every printed
// form is redacted.
type Provider struct {
	aeads   map[int]cipher.AEAD
	current int
}

// New builds the provider from configured KEKs and logs a warning that it is development-only.
// It refuses any environment other than development, so an unknown or empty environment fails
// closed.
func New(env config.Environment, keks config.KEKs, log *slog.Logger) (*Provider, error) {
	keys := make(map[int][]byte, keks.Len())
	for _, v := range keks.Versions() {
		s, _ := keks.Get(v)
		keys[v] = []byte(s.Reveal())
	}
	cur, _ := keks.Current()
	return NewFromKeys(env, keys, cur, log)
}

// NewFromKeys builds the provider from raw 32-byte KEKs keyed by version. It exists so tests and
// tools can build a provider without going through configuration; the environment check and the
// warning are the same as New. The provider keeps no reference to the key slices.
func NewFromKeys(env config.Environment, keys map[int][]byte, current int, log *slog.Logger) (*Provider, error) {
	if env != config.Development {
		return nil, ErrProduction
	}
	if len(keys) == 0 {
		return nil, errors.New("local key provider: no KEKs configured")
	}
	p := &Provider{aeads: make(map[int]cipher.AEAD, len(keys)), current: current}
	for v, k := range keys {
		if v < 1 {
			return nil, errors.New("local key provider: KEK versions must be positive")
		}
		if len(k) != config.KEKBytes {
			return nil, fmt.Errorf("local key provider: KEK version %d must be exactly %d bytes", v, config.KEKBytes)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("local key provider: KEK version %d is unusable", v)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("local key provider: KEK version %d is unusable", v)
		}
		p.aeads[v] = gcm
	}
	if _, ok := p.aeads[current]; !ok {
		return nil, errors.New("local key provider: the current KEK version is not in the key set")
	}
	if log != nil {
		log.Warn("local key provider is DEVELOPMENT-ONLY: KEKs are held in process memory and configuration; "+
			"never use it in production",
			slog.String("provider", Name), slog.Int("kek_versions", len(keys)), slog.Int("current_version", current))
	}
	return p, nil
}

// Name implements kms.Provider.
func (*Provider) Name() string { return Name }

// Current implements kms.Provider.
func (p *Provider) Current(ctx context.Context) (kms.KeyRef, error) {
	if err := kms.FromContext(ctx, Name, "current"); err != nil {
		return kms.KeyRef{}, err
	}
	return kms.KeyRef{KeyID: KeyID, Version: strconv.Itoa(p.current)}, nil
}

// bind prefixes the caller's associated data with the format byte, so the format version is
// authenticated too.
func bind(aad []byte) []byte {
	out := make([]byte, 0, 1+len(aad))
	out = append(out, formatV1)
	return append(out, aad...)
}

// Wrap implements kms.Provider.
func (p *Provider) Wrap(ctx context.Context, plaintext, aad []byte) (kms.Wrapped, error) {
	if err := kms.FromContext(ctx, Name, "wrap"); err != nil {
		return kms.Wrapped{}, err
	}
	if len(plaintext) == 0 {
		return kms.Wrapped{}, kms.New(kms.Invalid, Name, "wrap", "plaintext is empty")
	}
	if len(aad) == 0 {
		return kms.Wrapped{}, kms.New(kms.Invalid, Name, "wrap", "associated data is empty")
	}
	aead := p.aeads[p.current]
	out := make([]byte, 1+nonceSize, 1+nonceSize+len(plaintext)+tagSize)
	out[0] = formatV1
	if _, err := rand.Read(out[1 : 1+nonceSize]); err != nil {
		return kms.Wrapped{}, kms.New(kms.Other, Name, "wrap", "no randomness available")
	}
	out = aead.Seal(out, out[1:1+nonceSize], plaintext, bind(aad))
	return kms.Wrapped{
		Provider:   Name,
		KeyID:      KeyID,
		Version:    strconv.Itoa(p.current),
		Ciphertext: out,
	}, nil
}

// Unwrap implements kms.Provider. It never returns partial plaintext: on any failure the result is
// nil.
func (p *Provider) Unwrap(ctx context.Context, w kms.Wrapped, aad []byte) ([]byte, error) {
	if err := kms.FromContext(ctx, Name, "unwrap"); err != nil {
		return nil, err
	}
	if w.Provider != Name {
		return nil, kms.New(kms.Invalid, Name, "unwrap", "the key was not wrapped by this provider")
	}
	if w.KeyID != KeyID {
		return nil, kms.New(kms.NotConfigured, Name, "unwrap", "unknown KEK id")
	}
	version, err := strconv.Atoi(w.Version)
	if err != nil || version < 1 {
		return nil, kms.New(kms.Invalid, Name, "unwrap", "malformed KEK version")
	}
	aead, ok := p.aeads[version]
	if !ok {
		return nil, kms.New(kms.NotConfigured, Name, "unwrap", "the KEK version that wrapped this key is not configured")
	}
	if len(aad) == 0 {
		return nil, kms.New(kms.Invalid, Name, "unwrap", "associated data is empty")
	}
	ct := w.Ciphertext
	if len(ct) < 1+nonceSize+tagSize+1 || ct[0] != formatV1 {
		return nil, kms.New(kms.Invalid, Name, "unwrap", "malformed wrapped key")
	}
	pt, err := aead.Open(nil, ct[1:1+nonceSize], ct[1+nonceSize:], bind(aad))
	if err != nil {
		return nil, kms.New(kms.Invalid, Name, "unwrap", "authentication failed")
	}
	return pt, nil
}

// String implements fmt.Stringer. It shows versions, never keys.
func (p *Provider) String() string {
	return fmt.Sprintf("local-key-provider(development-only versions=%d current=%d keys=%s)",
		len(p.aeads), p.current, config.Redacted)
}

// GoString implements fmt.GoStringer.
func (p *Provider) GoString() string { return p.String() }

// Format implements fmt.Formatter and covers every verb.
func (p *Provider) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(p.String())) }

// LogValue implements slog.LogValuer.
func (p *Provider) LogValue() slog.Value { return slog.StringValue(p.String()) }

var _ kms.Provider = (*Provider)(nil)
