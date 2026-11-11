package httpx

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/reqid"
)

// WriteProblem writes err as an application/problem+json response carrying the request's ID.
// Anything that is not a registered *errs.Error becomes a generic internal_error; the cause is
// not part of the response.
func WriteProblem(w http.ResponseWriter, r *http.Request, err error) {
	id, _ := reqid.FromContext(r.Context())
	errs.Write(w, err, id)
}

// RequestErrorHandler is for the generated servers' request-binding failures (malformed
// parameters or bodies). It answers invalid_request with a fixed detail, so framework error text
// is never sent to the client or logged.
func RequestErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if isBodyTooLarge(err) {
		WriteProblem(w, r, errs.New(errs.PayloadTooLarge, "The request body is too large."))
		return
	}
	// The binding error is attached as the cause but not logged: it can quote the offending
	// parameter value.
	WriteProblem(w, r, errs.Wrap(errs.InvalidRequest, "The request is malformed.", err))
}

// ResponseErrorHandler is for errors returned by strict-server handlers. A registered *errs.Error
// is answered as is; anything else is answered as internal_error. The cause is logged, never sent.
func ResponseErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	var e *errs.Error
	attrs := []slog.Attr{slog.String("error", err.Error())}
	level := slog.LevelError
	if errors.As(err, &e) {
		attrs = []slog.Attr{slog.String("code", string(e.Code))}
		if cause := errors.Unwrap(e); cause != nil {
			attrs = append(attrs, slog.String("cause", cause.Error()))
		}
		if info, ok := errs.Lookup(e.Code); ok && info.Status < 500 {
			level = slog.LevelWarn
		}
	}
	Logger(r.Context()).LogAttrs(r.Context(), level, "request failed", attrs...)
	WriteProblem(w, r, err)
}
