package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretRedaction(t *testing.T) {
	const raw = "s3cr3t-distinctive-value"
	s := NewSecret(raw)
	if s.Reveal() != raw {
		t.Fatal("Reveal must return the value")
	}
	if (Secret{}).Reveal() != "" || !(Secret{}).IsEmpty() {
		t.Fatal("zero value must be empty")
	}
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
		outs = append(outs, fmt.Sprintf(verb, s), fmt.Sprintf(verb, &s), fmt.Sprintf(verb, []Secret{s}),
			fmt.Sprintf(verb, struct{ S Secret }{s}), fmt.Sprintf(verb, map[string]Secret{"k": s}))
	}
	outs = append(outs, s.String(), s.GoString(), fmt.Sprint(s), fmt.Sprintln(s))
	j, err := json.Marshal(map[string]any{"s": s, "p": &s})
	if err != nil {
		t.Fatal(err)
	}
	outs = append(outs, string(j))
	text, _ := s.MarshalText()
	outs = append(outs, string(text))
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "s", s, slog.Any("t", s))
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "s", s)
	outs = append(outs, buf.String())
	for _, o := range outs {
		if strings.Contains(o, raw) || strings.Contains(o, fmt.Sprintf("%x", raw)) {
			t.Fatal("secret leaked in a printed form")
		}
	}
	if got := fmt.Sprintf("%v", s); got != Redacted {
		t.Fatalf("got %q", got)
	}
}

// A Secret stored in an unexported field of another type must not leak through
// fmt's reflection fallback.
func TestSecretInUnexportedField(t *testing.T) {
	const raw = "unexported-field-distinctive-value"
	type holder struct {
		name string
		s    Secret
		m    map[string]Secret
		l    []Secret
	}
	h := holder{name: "x", s: NewSecret(raw), m: map[string]Secret{"k": NewSecret(raw)}, l: []Secret{NewSecret(raw)}}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		for _, o := range []string{fmt.Sprintf(verb, h), fmt.Sprintf(verb, &h)} {
			if strings.Contains(o, raw) || strings.Contains(o, fmt.Sprintf("%x", raw)) {
				t.Fatalf("secret leaked through %s on an unexported field", verb)
			}
		}
	}
}

func TestSecretEqual(t *testing.T) {
	if !NewSecret("a").Equal(NewSecret("a")) || NewSecret("a").Equal(NewSecret("b")) {
		t.Fatal("Equal must compare values")
	}
	if !(Secret{}).Equal(NewSecret("")) {
		t.Fatal("zero value must equal the empty secret")
	}
}
