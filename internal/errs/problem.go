package errs

import (
	"encoding/json"
	"errors"
	"net/http"
)

// ContentType is the media type of error responses (RFC 9457).
const ContentType = "application/problem+json"

// TypePrefix is prepended to the code to form the problem type URI.
const TypePrefix = "urn:cipherframe:error:"

// genericDetail is the only detail ever sent for unexpected errors.
const genericDetail = "An internal error occurred."

// Problem is an RFC 9457 problem details body with Cipherframe extensions.
type Problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail"`
	Code      Code   `json:"code"`
	Retryable bool   `json:"retryable"`
	RequestID string `json:"request_id"`
}

// ToProblem converts err to a Problem. It finds an *Error with errors.As. A nil error, a
// non-*Error error, or an *Error whose code is not registered becomes internal_error with a
// generic detail; the original error text is never included.
func ToProblem(err error, requestID string) Problem {
	code, detail := InternalError, genericDetail
	var e *Error
	if errors.As(err, &e) && e != nil {
		if _, ok := registry[e.Code]; ok {
			code, detail = e.Code, e.Detail
		}
	}
	info := registry[code]
	return Problem{
		Type:      TypePrefix + string(code),
		Title:     info.Title,
		Status:    info.Status,
		Detail:    detail,
		Code:      code,
		Retryable: info.Retryable,
		RequestID: requestID,
	}
}

// Write writes err as an application/problem+json response with the matching status.
func Write(w http.ResponseWriter, err error, requestID string) {
	p := ToProblem(err, requestID)
	body, mErr := json.Marshal(p)
	if mErr != nil { // cannot happen for this struct; fail closed
		http.Error(w, genericDetail, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(p.Status)
	_, _ = w.Write(append(body, '\n'))
}
