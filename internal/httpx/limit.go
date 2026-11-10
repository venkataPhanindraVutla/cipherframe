package httpx

import (
	"errors"
	"net/http"
)

// LimitBody caps request bodies at n bytes. A body that exceeds the cap makes the read fail with
// *http.MaxBytesError, which RequestErrorHandler answers as payload_too_large.
func LimitBody(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isBodyTooLarge(err error) bool {
	var mb *http.MaxBytesError
	return errors.As(err, &mb)
}
