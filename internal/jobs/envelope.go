package jobs

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"time"
	"uuid"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// EnvelopeVersion is the version of the job contract in spec/jobs/ that this code writes and reads.
const EnvelopeVersion = 1

// Task states of the hand-off table.
const (
	StatePending   = "pending"
	StateLeased    = "leased"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
)

// Result statuses.
const (
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
)

var (
	kindPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.]{2,63}$`)
	codePatternEx = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	traceparentRE = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
)

// Trace is the trace context carried across the hand-off.
type Trace struct {
	Traceparent string `json:"traceparent,omitempty"`
}

// Envelope is the document written to external_tasks.envelope. It mirrors
// spec/jobs/envelope.schema.json and must never carry secrets, tokens, signed URLs or source
// object keys.
type Envelope struct {
	EnvelopeVersion int             `json:"envelope_version"`
	TaskID          uuid.UUID       `json:"task_id"`
	Kind            string          `json:"kind"`
	TenantID        id.TenantID     `json:"tenant_id"`
	AssetID         *id.AssetID     `json:"asset_id,omitempty"`
	Attempt         int             `json:"attempt"`
	CreatedAt       time.Time       `json:"created_at"`
	Trace           Trace           `json:"trace"`
	Payload         json.RawMessage `json:"payload"`
}

// Validate checks the rules of the envelope schema that the Go types do not already enforce.
func (e *Envelope) Validate() error {
	switch {
	case e.EnvelopeVersion != EnvelopeVersion:
		return invalid("unsupported envelope version")
	case e.TaskID == uuid.Nil():
		return invalid("task id is required")
	case !kindPattern.MatchString(e.Kind):
		return invalid("kind is malformed")
	case e.TenantID.IsZero():
		return invalid("tenant id is required")
	case e.AssetID != nil && e.AssetID.IsZero():
		return invalid("asset id is zero")
	case e.Attempt < 1:
		return invalid("attempt must be at least 1")
	case e.CreatedAt.IsZero():
		return invalid("created_at is required")
	case e.Trace.Traceparent != "" && !traceparentRE.MatchString(e.Trace.Traceparent):
		return invalid("traceparent is malformed")
	}
	if !isJSONObject(e.Payload) {
		return invalid("payload must be a JSON object")
	}
	return nil
}

func isJSONObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || t[0] != '{' {
		return false
	}
	var m map[string]json.RawMessage
	return json.Unmarshal(t, &m) == nil
}

func invalid(msg string) error {
	return errs.New(errs.InvalidRequest, "invalid task envelope: "+msg)
}

// TaskError is the error object of a failed result. Message is for operators and must not hold
// secrets; this package never logs it and never copies it into a job's stored error.
type TaskError struct {
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
	Message   string `json:"message"`
}

// UnmarshalJSON requires every member of the error object, as the schema does: a missing
// "retryable" must not silently mean false.
func (e *TaskError) UnmarshalJSON(b []byte) error {
	var raw struct {
		Code      *string `json:"code"`
		Retryable *bool   `json:"retryable"`
		Message   *string `json:"message"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil || raw.Code == nil || raw.Retryable == nil || raw.Message == nil {
		return errors.New("jobs: malformed error object")
	}
	*e = TaskError{Code: *raw.Code, Retryable: *raw.Retryable, Message: *raw.Message}
	return nil
}

// Artifact is a derived artifact an external worker wrote to storage. The Go side must register it
// (invariant I6).
type Artifact struct {
	Kind         string `json:"kind"`
	Key          string `json:"key"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	ModelID      string `json:"model_id,omitempty"`
	ModelVersion string `json:"model_version,omitempty"`
}

// UnmarshalJSON requires the schema's mandatory members, so a missing size is not read as zero.
func (a *Artifact) UnmarshalJSON(b []byte) error {
	var raw struct {
		Kind         *string `json:"kind"`
		Key          *string `json:"key"`
		SHA256       *string `json:"sha256"`
		SizeBytes    *int64  `json:"size_bytes"`
		ModelID      string  `json:"model_id"`
		ModelVersion string  `json:"model_version"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil || raw.Kind == nil || raw.Key == nil || raw.SHA256 == nil || raw.SizeBytes == nil {
		return errors.New("jobs: malformed artifact")
	}
	*a = Artifact{
		Kind: *raw.Kind, Key: *raw.Key, SHA256: *raw.SHA256, SizeBytes: *raw.SizeBytes,
		ModelID: raw.ModelID, ModelVersion: raw.ModelVersion,
	}
	return nil
}

// Result is the document an external worker writes to external_tasks.result. It mirrors
// spec/jobs/result.schema.json.
type Result struct {
	EnvelopeVersion int        `json:"envelope_version"`
	TaskID          uuid.UUID  `json:"task_id"`
	Status          string     `json:"status"`
	Error           *TaskError `json:"error,omitempty"`
	// Output is the kind-specific output of a succeeded task (for example the face count of
	// media.mask_faces). Each kind defines and validates its own shape.
	Output    json.RawMessage `json:"output,omitempty"`
	Artifacts []Artifact      `json:"artifacts,omitempty"`
}

// Validate checks the result against the rules of the result schema.
func (r *Result) Validate() error {
	if r.EnvelopeVersion != EnvelopeVersion {
		return invalidResult("unsupported envelope version")
	}
	if r.TaskID == uuid.Nil() {
		return invalidResult("task id is required")
	}
	switch r.Status {
	case StatusSucceeded:
		if r.Error != nil {
			return invalidResult("a succeeded result must not carry an error")
		}
	case StatusFailed:
		if r.Error == nil {
			return invalidResult("a failed result needs an error")
		}
		if !codePatternEx.MatchString(r.Error.Code) {
			return invalidResult("error code is malformed")
		}
		if len(r.Error.Message) > 1024 {
			return invalidResult("error message is too long")
		}
	default:
		return invalidResult("status must be succeeded or failed")
	}
	if len(r.Output) > 0 && (r.Status != StatusSucceeded || bytes.TrimSpace(r.Output)[0] != '{') {
		return invalidResult("output must be an object on a succeeded result")
	}
	for _, a := range r.Artifacts {
		switch {
		case !kindPattern.MatchString(a.Kind):
			return invalidResult("artifact kind is malformed")
		case a.Key == "" || len(a.Key) > 1024:
			return invalidResult("artifact key is missing or too long")
		case !sha256Pattern.MatchString(a.SHA256):
			return invalidResult("artifact sha256 must be 64 lower-case hex characters")
		case a.SizeBytes < 0:
			return invalidResult("artifact size must not be negative")
		}
	}
	return nil
}

func invalidResult(msg string) error {
	return errs.New(errs.InvalidRequest, "invalid task result: "+msg)
}

// ParseResult decodes a stored result strictly (unknown fields are rejected, as the schema's
// additionalProperties: false requires) and validates it.
func ParseResult(raw []byte) (Result, error) {
	var r Result
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		// The decoder's text can quote the document; do not pass it on.
		return Result{}, invalidResult("not a result document")
	}
	if dec.More() {
		return Result{}, invalidResult("trailing data")
	}
	if err := r.Validate(); err != nil {
		return Result{}, err
	}
	return r, nil
}

// errNoLease is returned (as a conflict) when a worker's lease on a task is not valid any more.
var errNoLease = errors.New("jobs: lease not held")

func leaseLost() error {
	return errs.Wrap(errs.Conflict, "the task lease is not held by this worker", errNoLease)
}
