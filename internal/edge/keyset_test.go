package edge_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
)

// Without a key set the route answers 503 with a problem, never an empty key list: a verifier
// must not read "no keys" as a valid answer.
func TestKeySetWithoutSourceIsUnavailable(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(edge.New(edge.Deps{Log: log}).Handler())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/.well-known/cipherframe-keys.json") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type = %q", ct)
	}
}
