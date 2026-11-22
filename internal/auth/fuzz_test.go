package auth

import (
	"strings"
	"testing"
)

// FuzzBearerToken: the returned token holds no whitespace and is the header's tail.
func FuzzBearerToken(f *testing.F) {
	f.Add("Bearer test-fixture-token")
	f.Add("bearer  two spaces")
	f.Add("Bearer a\tb")
	f.Fuzz(func(t *testing.T, h string) {
		tok, ok := BearerToken(h)
		if !ok {
			return
		}
		if h[len("bearer "):] != tok || strings.ContainsAny(tok, " \t\r\n") {
			t.Fatal("token is not the header's whitespace-free tail")
		}
	})
}
