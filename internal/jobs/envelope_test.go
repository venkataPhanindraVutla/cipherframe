package jobs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

const specDir = "../../spec/jobs"

func compileSchema(t *testing.T, file, url string) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(specDir, file))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(url)
	if err != nil {
		t.Fatalf("compile %s: %v", file, err)
	}
	return s
}

func envelopeSchema(t *testing.T) *jsonschema.Schema {
	return compileSchema(t, "envelope.schema.json", "urn:cipherframe:spec:jobs:envelope:1")
}

func resultSchema(t *testing.T) *jsonschema.Schema {
	return compileSchema(t, "result.schema.json", "urn:cipherframe:spec:jobs:result:1")
}

func validateJSON(s *jsonschema.Schema, raw []byte) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return s.Validate(inst)
}

func TestVectors(t *testing.T) {
	schemas := map[string]*jsonschema.Schema{
		"envelope-": envelopeSchema(t),
		"result-":   resultSchema(t),
	}
	for _, dir := range []string{"valid", "invalid"} {
		files, err := filepath.Glob(filepath.Join(specDir, "vectors", dir, "*.json"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no vectors in %s (%v)", dir, err)
		}
		for _, f := range files {
			name := filepath.Base(f)
			t.Run(dir+"/"+name, func(t *testing.T) {
				var schema *jsonschema.Schema
				for prefix, s := range schemas {
					if strings.HasPrefix(name, prefix) {
						schema = s
					}
				}
				if schema == nil {
					t.Fatalf("vector %s has no schema prefix", name)
				}
				raw, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				err = validateJSON(schema, raw)
				if dir == "valid" && err != nil {
					t.Fatalf("valid vector rejected: %v", err)
				}
				if dir == "invalid" && err == nil {
					t.Fatal("invalid vector accepted")
				}
			})
		}
	}
}

func TestVectorsAgreeWithGoValidation(t *testing.T) {
	// The Go-side checks mirror the schema; the valid vectors must pass them too.
	for _, name := range []string{"envelope-minimal", "envelope-full"} {
		raw, err := os.ReadFile(filepath.Join(specDir, "vectors", "valid", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var e Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := e.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(specDir, "vectors", "valid", "result-*.json"))
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		if _, err := ParseResult(raw); err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
	}
	files, _ = filepath.Glob(filepath.Join(specDir, "vectors", "invalid", "result-*.json"))
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		if _, err := ParseResult(raw); err == nil {
			t.Fatalf("%s: Go parser accepted an invalid vector", filepath.Base(f))
		}
	}
}

func sampleEnvelope() Envelope {
	asset := id.New[id.AssetKind]()
	return Envelope{
		EnvelopeVersion: EnvelopeVersion,
		TaskID:          uuid.NewV7(),
		Kind:            "ml.embed",
		TenantID:        id.New[id.TenantKind](),
		AssetID:         &asset,
		Attempt:         2,
		CreatedAt:       time.Date(2026, 11, 10, 9, 30, 0, 123456000, time.UTC),
		Trace:           Trace{Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		Payload:         json.RawMessage(`{"language":"en"}`),
	}
}

func TestEnvelopeMarshalsToSchema(t *testing.T) {
	schema := envelopeSchema(t)
	withAsset := sampleEnvelope()
	noAsset := sampleEnvelope()
	noAsset.AssetID = nil
	noAsset.Trace = Trace{}
	for name, e := range map[string]Envelope{"with asset": withAsset, "minimal": noAsset} {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := validateJSON(schema, raw); err != nil {
			t.Fatalf("%s: envelope does not follow the schema: %v\n%s", name, err, raw)
		}
		var back Envelope
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		if back.TaskID != e.TaskID || back.TenantID != e.TenantID || back.Kind != e.Kind {
			t.Fatalf("%s: round trip changed the envelope", name)
		}
	}
	noAssetRaw, _ := json.Marshal(noAsset)
	if bytes.Contains(noAssetRaw, []byte("asset_id")) {
		t.Fatal("an absent asset id must be omitted")
	}
}

func TestEnvelopeValidate(t *testing.T) {
	mutate := map[string]func(*Envelope){
		"version":     func(e *Envelope) { e.EnvelopeVersion = 2 },
		"task id":     func(e *Envelope) { e.TaskID = uuid.Nil() },
		"kind":        func(e *Envelope) { e.Kind = "Bad Kind" },
		"tenant":      func(e *Envelope) { e.TenantID = id.TenantID{} },
		"attempt":     func(e *Envelope) { e.Attempt = 0 },
		"created":     func(e *Envelope) { e.CreatedAt = time.Time{} },
		"traceparent": func(e *Envelope) { e.Trace.Traceparent = "nope" },
		"payload":     func(e *Envelope) { e.Payload = json.RawMessage(`[1]`) },
		"no payload":  func(e *Envelope) { e.Payload = nil },
	}
	for name, m := range mutate {
		e := sampleEnvelope()
		m(&e)
		if err := e.Validate(); err == nil {
			t.Errorf("%s: invalid envelope accepted", name)
		}
	}
	ok := sampleEnvelope()
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
}

func TestResultMarshalsToSchema(t *testing.T) {
	schema := resultSchema(t)
	taskID := uuid.NewV7()
	sha := strings.Repeat("ab", 32)
	results := map[string]Result{
		"succeeded": {EnvelopeVersion: 1, TaskID: taskID, Status: StatusSucceeded, Artifacts: []Artifact{
			{Kind: "ml.embedding", Key: "derived/a", SHA256: sha, SizeBytes: 10, ModelID: "m", ModelVersion: "1"},
			{Kind: "ml.transcript", Key: "derived/b", SHA256: sha, SizeBytes: 0},
		}},
		"empty": {EnvelopeVersion: 1, TaskID: taskID, Status: StatusSucceeded},
		"failed": {EnvelopeVersion: 1, TaskID: taskID, Status: StatusFailed,
			Error: &TaskError{Code: "model_unavailable", Retryable: true, Message: "later"}},
	}
	for name, r := range results {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateJSON(schema, raw); err != nil {
			t.Fatalf("%s: result does not follow the schema: %v\n%s", name, err, raw)
		}
		if _, err := ParseResult(raw); err != nil {
			t.Fatalf("%s: ParseResult: %v", name, err)
		}
	}
}

func TestParseResultRejects(t *testing.T) {
	id1 := uuid.NewV7().String()
	for name, doc := range map[string]string{
		"unknown field": `{"envelope_version":1,"task_id":"` + id1 + `","status":"succeeded","token":"x"}`,
		"not json":      `nope`,
		"trailing":      `{"envelope_version":1,"task_id":"` + id1 + `","status":"succeeded"} {}`,
		"failed no err": `{"envelope_version":1,"task_id":"` + id1 + `","status":"failed"}`,
		"bad sha":       `{"envelope_version":1,"task_id":"` + id1 + `","status":"succeeded","artifacts":[{"kind":"ml.x","key":"k","sha256":"zz","size_bytes":1}]}`,
	} {
		if _, err := ParseResult([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
