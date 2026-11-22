package telemetry

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsPath is where the scrape endpoint is mounted.
const MetricsPath = "/metrics"

// MetricsHandler serves the registry to a caller that presents the scrape token as a bearer
// token. The comparison is constant time. Any other request, whatever is wrong with it, gets a
// bare 401 that says nothing about why. With no token configured it refuses everything.
func (t *Telemetry) MetricsHandler() http.Handler {
	prom := promhttp.HandlerFor(t.Registry, promhttp.HandlerOpts{})
	want, hasToken := t.tokenHash, t.hasToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, got, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		// Hashing first makes the comparison length-independent.
		sum := sha256.Sum256([]byte(got))
		if !hasToken || !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare(sum[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		prom.ServeHTTP(w, r)
	})
}

// Mount serves /metrics next to h. When no scrape token is configured the route does not exist
// and h is returned unchanged, so /metrics is whatever h makes of it (a 404).
func (t *Telemetry) Mount(h http.Handler) http.Handler {
	if !t.MetricsEnabled() {
		return h
	}
	mux := http.NewServeMux()
	mux.Handle(MetricsPath, t.MetricsHandler())
	mux.Handle("/", h)
	return mux
}
