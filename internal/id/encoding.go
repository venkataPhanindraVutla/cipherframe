package id

import "errors"

// alphabet is lowercase Crockford base32. It omits i, l, o and u. Characters are in ascending
// ASCII order, so for equal-length strings text order matches byte order.
const alphabet = "0123456789abcdefghjkmnpqrstvwxyz"

var errBadEncoding = errors.New("invalid base32 text")

// decodeTable maps an ASCII byte to its 5-bit value, or 0xff if it is not in the alphabet.
var decodeTable = func() [256]byte {
	var t [256]byte
	for i := range t {
		t[i] = 0xff
	}
	for i := 0; i < len(alphabet); i++ {
		t[alphabet[i]] = byte(i)
	}
	return t
}()

// encodedLen returns the unpadded base32 length of n bytes.
func encodedLen(n int) int { return (n*8 + 4) / 5 }

// encode writes src as big-endian base32 without padding. Trailing bits of the last character
// are zero.
func encode(src []byte) string {
	out := make([]byte, 0, encodedLen(len(src)))
	var acc uint32
	var bits uint
	for _, b := range src {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, alphabet[(acc>>bits)&31])
		}
		acc &= 1<<bits - 1
	}
	if bits > 0 {
		out = append(out, alphabet[(acc<<(5-bits))&31])
	}
	return string(out)
}

// decode reverses encode into dst (len(dst) bytes). It requires exactly encodedLen(len(dst))
// characters, all in the alphabet, and zero trailing bits (canonical form).
func decode(dst []byte, s string) error {
	if len(s) != encodedLen(len(dst)) {
		return errBadEncoding
	}
	var acc uint32
	var bits uint
	n := 0
	for i := 0; i < len(s); i++ {
		v := decodeTable[s[i]]
		if v == 0xff {
			return errBadEncoding
		}
		acc = acc<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			dst[n] = byte((acc >> bits) & 0xff)
			n++
			acc &= 1<<bits - 1
		}
	}
	if acc != 0 {
		return errBadEncoding // non-zero trailing bits
	}
	return nil
}
