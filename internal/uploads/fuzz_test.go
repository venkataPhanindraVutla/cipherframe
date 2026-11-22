package uploads

import (
	"bytes"
	"testing"
)

// FuzzHashToken: a token HashToken accepts has the exact canonical length, and the hash is the
// SHA-256 of it.
func FuzzHashToken(f *testing.F) {
	tok, err := NewToken()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(tok.Reveal())
	f.Add("")
	f.Add("cfu_")
	f.Fuzz(func(t *testing.T, s string) {
		h, err := HashToken(s)
		if err != nil {
			return
		}
		if len(s) != TokenLen || !bytes.Equal(h, sum(s)) {
			t.Fatal("accepted a non-canonical token")
		}
	})
}
