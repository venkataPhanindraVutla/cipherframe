package edge

import (
	"net/http"
	"strings"
)

// multipartPrefix is the path prefix of the multipart upload endpoints.
const multipartPrefix = "/v1/uploads/multipart/"

// uploadCORS lets a browser page call the multipart upload endpoints (the tus endpoints get their
// CORS headers from tusd). Requests are authenticated by the upload token in the Authorization
// header, never by cookies or ambient credentials, so any origin may call: the wildcard origin
// never carries credentials. The preflight needs no token.
func uploadCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, multipartPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Add("Vary", "Origin")
		h.Set("Access-Control-Expose-Headers", "ETag, X-Request-Id")
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Content-Length, X-Request-Id")
			h.Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
