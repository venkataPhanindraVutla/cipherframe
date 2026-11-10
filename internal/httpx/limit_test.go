package httpx

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

func TestLimitBodyAnswersPayloadTooLarge(t *testing.T) {
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			RequestErrorHandler(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), append(Standard(testLoggerDiscard()), LimitBody(10))...)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader("0123456789")))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("body at the limit: status %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader("0123456789x")))
	if rec.Code != http.StatusRequestEntityTooLarge || problemOf(t, rec).Code != errs.PayloadTooLarge {
		t.Fatalf("oversized body: %d %s", rec.Code, rec.Body.String())
	}
}

func testLoggerDiscard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
