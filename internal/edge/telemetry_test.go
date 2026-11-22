package edge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/venkataPhanindraVutla/cipherframe/internal/telemetry"
)

// Pitfall 9: a playback request carries the session ID in the path and a token in the query and
// in the Authorization header; none of them may reach a span, and the span is named by the route
// template.
func TestPlaybackSpansCarryNoRequestData(t *testing.T) {
	const (
		session = "ses_testfixturesessionid00000"
		secret  = "test-fixture-playback-token"
	)
	exp := tracetest.NewInMemoryExporter()
	tel, err := telemetry.Setup(context.Background(), telemetry.Options{SpanExporter: exp, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })

	h := New(Deps{}).Handler()
	for _, target := range []string{
		"/v1/play/" + session + "/key?t=" + secret + "&X-Amz-Signature=test-fixture-sig",
		"/v1/play/" + session + "/master.m3u8?t=" + secret,
		"/v1/play/" + session + "/1080p/seg_00001.m4s",
		"/v1/no/such/route/" + session + "?t=" + secret,
	} {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("User-Agent", "test-fixture-agent")
		r.RemoteAddr = "192.0.2.77:4242"
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if err := tel.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	spans := exp.GetSpans()
	if len(spans) != 4 {
		t.Fatalf("spans = %d, want 4", len(spans))
	}
	forbidden := []string{session, secret, "test-fixture", "192.0.2.77", "?", "X-Amz", "ses_"}
	for _, s := range spans {
		texts := []string{s.Name}
		for _, a := range s.Attributes {
			texts = append(texts, string(a.Key), a.Value.Emit())
		}
		for _, text := range texts {
			for _, f := range forbidden {
				if strings.Contains(text, f) {
					t.Errorf("span %q: %q contains %q", s.Name, text, f)
				}
			}
		}
	}
	if got := spans[0].Name; got != "GET /v1/play/{session_id}/key" {
		t.Errorf("key span name = %q", got)
	}
	if got := spans[3].Name; got != "GET other" {
		t.Errorf("unmatched span name = %q", got)
	}
}
