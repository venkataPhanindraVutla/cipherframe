package jobs

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// failure is the only error value River ever stores for a failed attempt. It holds the error code
// and nothing else, because the text of a handler's error can carry secrets, signed URLs or object
// keys (invariant I9) and River persists error text.
type failure struct {
	code string
}

func (f failure) Error() string { return "failure code=" + f.code }

// codePattern extracts the code from a stored failure. Codes are lower_snake_case.
var codePattern = regexp.MustCompile(`code=([a-z][a-z0-9_]{0,63})`)

// codeFromStored returns the error code in a stored attempt error, or "" when there is none.
func codeFromStored(s string) string {
	if m := codePattern.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// Snooze asks for the job to run again after d without counting an attempt. Return it from a
// handler to wait for something.
func Snooze(d time.Duration) error { return river.JobSnooze(d) }

// Cancel returns an error that cancels the job at once whatever its remaining attempts. Only the
// code of err (when it is an *errs.Error) is kept; its text is dropped.
func Cancel(err error) error { return cancelWith(codeOf(err)) }

// cancelWith cancels the job and records code as its last error.
func cancelWith(code string) error { return river.JobCancel(failure{code: code}) }

// Retryable reports whether err should be retried: a registered code with Retryable set, an
// unregistered code, or any error that is not an *errs.Error. Only a registered, non-retryable
// code is final.
func Retryable(err error) bool {
	var e *errs.Error
	if !errors.As(err, &e) {
		return true
	}
	info, ok := errs.Lookup(e.Code)
	return !ok || info.Retryable
}

// codeOf returns the registered code of err, or InternalError for anything else.
func codeOf(err error) string {
	var f failure
	if errors.As(err, &f) {
		return f.code
	}
	var e *errs.Error
	if errors.As(err, &e) {
		if _, ok := errs.Lookup(e.Code); ok {
			return string(e.Code)
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return string(errs.Timeout)
	}
	return string(errs.InternalError)
}

// classify applies the error policy to what a handler returned.
func classify(err error) error {
	if err == nil {
		return nil
	}
	// River control flow returned deliberately by the handler passes through; a cancel is
	// rewritten so that it keeps only a code.
	var snooze *rivertype.JobSnoozeError
	if errors.As(err, &snooze) {
		return err
	}
	var cancel *rivertype.JobCancelError
	if errors.As(err, &cancel) {
		return Cancel(cancel)
	}
	f := failure{code: codeOf(err)}
	if !Retryable(err) {
		return river.JobCancel(f)
	}
	return f
}
