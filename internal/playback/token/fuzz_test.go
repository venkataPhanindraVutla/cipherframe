package token

import (
	"testing"
	"time"
)

// FuzzOpen feeds arbitrary strings to the verifier. Whatever it is given, it must not panic, and
// a token it accepts must be one this keyring signed: re-signing the returned claims gives the
// same token.
func FuzzOpen(f *testing.F) {
	k := testKeyring(f, 1, 1, 2)
	tok, err := k.Sign(claims(f, allScopes))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(tok, uint8(allScopes))
	f.Add("", uint8(1))
	f.Add(Version+"...", uint8(1))
	f.Fuzz(func(t *testing.T, tok string, need uint8) {
		c, err := k.Open(tok, t0, Scope(need))
		if err != nil {
			if !isInvalid(err) {
				t.Fatalf("error is not ErrInvalid: %v", err)
			}
			return
		}
		if c.Expiry.Before(t0) || !c.Scopes.Has(Scope(need)) {
			t.Fatalf("accepted a token that is expired or lacks scope: %+v", c)
		}
		again, err := k.Sign(c)
		if err != nil || again != tok {
			t.Fatalf("accepted a token this keyring did not sign: %v", err)
		}
	})
}

// FuzzTamper changes one byte of a valid token. The changed token never verifies; the intact one
// never verifies at or after its expiry, nor for another asset.
func FuzzTamper(f *testing.F) {
	k := testKeyring(f, 1, 1)
	c := claims(f, allScopes)
	tok, err := k.Sign(c)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(0, byte(1))
	f.Add(len(tok)/2, byte(0x20))
	f.Add(len(tok)-1, byte(0xff))
	f.Fuzz(func(t *testing.T, pos int, x byte) {
		if x == 0 {
			return
		}
		if pos < 0 {
			pos = -(pos + 1)
		}
		b := []byte(tok)
		b[pos%len(b)] ^= x
		if _, err := k.Verify(string(b), t0, ScopeKey, c.AssetID); err == nil {
			t.Fatalf("tampered token verified (byte %d, xor %#x)", pos%len(b), x)
		}
		if _, err := k.Verify(tok, c.Expiry.Add(time.Duration(pos%1000)*time.Second), ScopeKey, c.AssetID); err == nil {
			t.Fatal("expired token verified")
		}
		if _, err := k.Verify(tok, t0, ScopeKey, c.AssetID+"x"); err == nil {
			t.Fatal("token verified for another asset")
		}
	})
}
