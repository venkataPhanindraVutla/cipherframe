// Package hls holds the pure, FFmpeg-free parts of Cipherframe's HLS output (ADR 0024): the AES-128
// segment cipher, the canonical playlists and the codec strings. Everything here is deterministic
// given its inputs (apart from IV generation), so it is covered by golden-file and known-vector
// unit tests.
package hls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

const (
	// KeyBytes is the AES-128 key length.
	KeyBytes = 16
	// IVBytes is the IV length: one AES block.
	IVBytes = aes.BlockSize
)

// IV is the explicit initialization vector of one segment, written in the playlist as 0x<32 hex>.
type IV [IVBytes]byte

// NewIV returns a fresh random IV. Each segment gets its own (RFC 8216 section 5.2 allows an
// explicit IV per key tag): reusing a CBC IV under one key leaks whether two segments start with the
// same plaintext block, and every fMP4 segment starts with the same box header.
func NewIV() (IV, error) {
	var iv IV
	if _, err := rand.Read(iv[:]); err != nil {
		return IV{}, errors.New("hls: no randomness available")
	}
	return iv, nil
}

// EncryptSegment encrypts plain with AES-128-CBC and PKCS#7 padding, the HLS "AES-128" method
// (RFC 8216 section 4.3.2.4). The result is a fresh buffer of len(plain) rounded up to the next
// multiple of 16, always longer than plain (a full block of padding is added to an aligned input).
//
// The padded plaintext is built in the result buffer and encrypted in place, so no second copy of
// the plaintext exists besides the caller's own. The caller still owns plain and should clear it.
func EncryptSegment(key []byte, iv IV, plain []byte) ([]byte, error) {
	block, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	out := make([]byte, len(plain)+pad)
	copy(out, plain)
	for i := len(plain); i < len(out); i++ {
		out[i] = byte(pad)
	}
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(out, out)
	return out, nil
}

// DecryptSegment reverses EncryptSegment and checks the padding. It exists for verification (tests
// and integrity checks); players do their own decryption.
func DecryptSegment(key []byte, iv IV, ct []byte) ([]byte, error) {
	block, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("hls: ciphertext is not a whole number of blocks")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(out, ct)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(out) {
		clear(out)
		return nil, errors.New("hls: invalid padding")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			clear(out)
			return nil, errors.New("hls: invalid padding")
		}
	}
	return out[:len(out)-pad], nil
}

func newBlock(key []byte) (cipher.Block, error) {
	if len(key) != KeyBytes {
		return nil, errors.New("hls: the content key must be 16 bytes")
	}
	return aes.NewCipher(key)
}
