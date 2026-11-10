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
