package id

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSessionRoundTrip(t *testing.T) {
	a, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	s := a.String()
	if len(s) != 4+52 || !strings.HasPrefix(s, "ses_") {
		t.Fatalf("unexpected form %q", s)
	}
	b, err := ParseSession(s)
	if err != nil || !a.Equal(b) {
		t.Fatalf("round trip failed: %v", err)
	}
	c, _ := NewSession()
	if a.Equal(c) {
		t.Fatal("two sessions equal")
	}
}

func TestSessionStrict(t *testing.T) {
	a, _ := NewSession()
	s := a.String()
	bad := []string{
		"", "ses_", strings.ToUpper(s), s[:len(s)-1], s + "0",
		"ast_" + s[4:], "ses-" + s[4:],
		"ses_" + strings.Repeat("0", 52),       // nil
		"ses_" + strings.Repeat("1", 51) + "1", // trailing bits (4 low bits must be zero)
		"ses_" + strings.Repeat("1", 51) + "u",
	}
	for _, in := range bad {
		if _, err := ParseSession(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
	if _, err := ParseSession("ses_" + strings.Repeat("1", 51) + "g"); err != nil {
		t.Fatalf("canonical rejected: %v", err)
	}
}

func TestSessionZeroAndJSON(t *testing.T) {
	var z SessionID
	if _, err := json.Marshal(z); err == nil {
		t.Fatal("zero session marshalled")
	}
	a, _ := NewSession()
	b, err := json.Marshal(struct{ S SessionID }{a})
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ S SessionID }
	if err := json.Unmarshal(b, &out); err != nil || !out.S.Equal(a) {
		t.Fatalf("json round trip: %v", err)
	}
}

func TestSessionGoStringHidesSecret(t *testing.T) {
	a, _ := NewSession()
	if strings.Contains(fmt.Sprintf("%#v", a), a.String()[4:12]) {
		t.Fatal("GoString leaks")
	}
}

func TestSessionIDLogRedacted(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "session", s)
	if strings.Contains(buf.String(), s.String()) || !strings.Contains(buf.String(), "ses_[redacted]") {
		t.Fatal("session ID must be redacted in logs")
	}
}
