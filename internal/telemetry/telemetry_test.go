package telemetry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/telemetry"
)

const testToken = "test-fixture-scrape-token"

func setup(t *testing.T, o telemetry.Options) (*telemetry.Telemetry, *tracetest.InMemoryExporter) {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	o.SpanExporter = exp
	o.Getenv = func(string) string { return "" }
	tel, err := telemetry.Setup(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })
	return tel, exp
}

func scrape(h http.Handler, authz string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMetricsHandlerToken(t *testing.T) {
	tel, _ := setup(t, telemetry.Options{MetricsToken: testToken})
	h := tel.Mount(http.NotFoundHandler())
	for name, authz := range map[string]string{
		"missing": "", "wrong": "Bearer test-fixture-wrong-token", "wrong scheme": "Basic " + testToken,
		"no scheme": testToken, "empty": "Bearer ",
	} {
		w := scrape(h, authz)
		if w.Code != http.StatusUnauthorized || w.Body.Len() != 0 {
			t.Errorf("%s: status %d, body %q", name, w.Code, w.Body.String())
		}
	}
	w := scrape(h, "Bearer "+testToken)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "go_goroutines") {
		t.Fatalf("right token: status %d", w.Code)
	}
}

func TestMetricsNotMountedWithoutToken(t *testing.T) {
	tel, _ := setup(t, telemetry.Options{})
	if tel.MetricsEnabled() {
		t.Fatal("enabled without a token")
	}
	for _, authz := range []string{"", "Bearer ", "Bearer anything"} {
		if w := scrape(tel.Mount(http.NotFoundHandler()), authz); w.Code != http.StatusNotFound {
			t.Fatalf("status %d, want 404 (route not mounted)", w.Code)
		}
	}
	// Even the handler itself refuses everything when there is no token.
	if w := scrape(tel.MetricsHandler(), "Bearer "); w.Code != http.StatusUnauthorized {
		t.Fatalf("handler status %d", w.Code)
	}
}

func TestRouteTemplateLabelAndSpanName(t *testing.T) {
	tel, exp := setup(t, telemetry.Options{})
	rt := httpx.NewRouter()
	rt.HandleFunc("GET /v1/play/{session_id}/key", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := telemetry.Middleware("edge")(rt)

	do := func(method, target string) {
		r := httptest.NewRequestWithContext(context.Background(), method, target, nil)
		r.Header.Set("Authorization", "Bearer test-fixture-secret")
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	do("GET", "/v1/play/ses_secretsessionid/key?t=test-fixture-token")
	do("GET", "/v1/play/ses_another/key")
	do("GET", "/nothing/test-fixture-path-secret")
	do("BREW", "/v1/play/ses_x/key")

	if err := tel.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range exp.GetSpans() {
		names = append(names, s.Name)
		for _, a := range s.Attributes {
			if strings.Contains(a.Value.Emit(), "ses_") || strings.Contains(a.Value.Emit(), "test-fixture") {
				t.Errorf("attribute %s leaks request data: %s", a.Key, a.Value.Emit())
			}
		}
	}
	want := []string{"GET /v1/play/{session_id}/key", "GET /v1/play/{session_id}/key", "GET other", "OTHER other"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("span names = %q, want %q", names, want)
	}
	if n := countSeries(t, tel, "cipherframe_http_request_duration_seconds"); n != 3 {
		t.Fatalf("series = %d, want 3 (one per route and method)", n)
	}
	if n := countSeries(t, tel, "cipherframe_key_request_duration_seconds"); n != 1 {
		t.Fatalf("key series = %d", n)
	}
}

func TestTraceContextRoundTripThroughJobMetadata(t *testing.T) {
	tel, exp := setup(t, telemetry.Options{})
	ctx, endReq := telemetry.StartFFmpeg(context.Background(), "probe") // any span stands in for the request
	meta := telemetry.JobMetadata(ctx)
	if meta == nil {
		t.Fatal("no metadata with an active span")
	}
	endReq(nil)

	_, end := telemetry.StartJob(context.Background(), "asset.process", meta, 2)
	end(telemetry.OutcomeSucceeded)
	if err := tel.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	spans := exp.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("spans = %d", len(spans))
	}
	parent, job := spans[0], spans[1]
	if job.Name != "job asset.process" || job.SpanContext.TraceID() != parent.SpanContext.TraceID() || job.Parent.SpanID() != parent.SpanContext.SpanID() {
		t.Fatalf("the job span is not a child of the inserting span: %+v", job)
	}
	if telemetry.JobMetadata(context.Background()) != nil {
		t.Error("metadata without a span")
	}
}

func TestStartJobIgnoresBadMetadata(t *testing.T) {
	setup(t, telemetry.Options{})
	for _, m := range [][]byte{nil, []byte("not json"), []byte(`{"traceparent":"garbage"}`), []byte(`[]`)} {
		_, end := telemetry.StartJob(context.Background(), "k", m, 1)
		end(telemetry.OutcomeFailed)
	}
}

func TestTenantLabelSwitch(t *testing.T) {
	for _, on := range []bool{false, true} {
		tel, _ := setup(t, telemetry.Options{TenantLabel: on, MetricsToken: testToken})
		telemetry.Refusal(telemetry.ReasonQuotaExceeded, "ten_test")
		telemetry.Refusal(telemetry.ReasonRateLimited, "ten_other")
		out := scrapeText(t, tel)
		if has := strings.Contains(out, "tenant_id"); has != on {
			t.Errorf("tenant label on=%v but exposition has it=%v", on, has)
		}
		if on && !strings.Contains(out, `cipherframe_refusals_total{reason="quota_exceeded",tenant_id="ten_test"} 1`) {
			t.Errorf("missing tenant series:\n%s", out)
		}
		if !on && !strings.Contains(out, `cipherframe_refusals_total{reason="quota_exceeded"} 1`) {
			t.Errorf("missing series:\n%s", out)
		}
	}
}

func scrapeText(t *testing.T, tel *telemetry.Telemetry) string {
	t.Helper()
	return scrape(tel.MetricsHandler(), "Bearer "+testToken).Body.String()
}

func countSeries(t *testing.T, tel *telemetry.Telemetry, name string) int {
	t.Helper()
	fams, err := tel.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() == name {
			return len(f.GetMetric())
		}
	}
	return 0
}
