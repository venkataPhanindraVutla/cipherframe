package id

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
)

const (
	sessionPrefix  = "ses"
	sessionBytes   = 32
	sessionTextLen = 52
)

// SessionID is a 256-bit random capability: holding it grants playback. It has no ordering and no
// time component, and is never derived from a UUID. Do not log it.
type SessionID struct {
	b [sessionBytes]byte
}

// ErrZeroSession is returned when marshalling the zero SessionID.
var ErrZeroSession = errors.New("id: zero session ID")

// NewSession returns a SessionID from crypto/rand. It returns an error only if the system
// random source fails; callers must fail closed.
func NewSession() (SessionID, error) {
	var s SessionID
	if _, err := rand.Read(s.b[:]); err != nil {
		return SessionID{}, fmt.Errorf("id: generate session ID: %w", err)
	}
	return s, nil
}

// ParseSession is the strict parser for the text form ses_<52 chars>. Errors never contain the
// input.
func ParseSession(s string) (SessionID, error) {
	if len(s) != len(sessionPrefix)+1+sessionTextLen || s[:len(sessionPrefix)] != sessionPrefix ||
		s[len(sessionPrefix)] != '_' {
		return SessionID{}, fmt.Errorf("%w: want %s_ followed by %d characters", ErrFormat, sessionPrefix, sessionTextLen)
	}
	var out SessionID
	if err := decode(out.b[:], s[len(sessionPrefix)+1:]); err != nil {
		return SessionID{}, fmt.Errorf("%w: invalid %s_ identifier body", ErrFormat, sessionPrefix)
	}
	if out.IsZero() {
		return SessionID{}, fmt.Errorf("%w: nil identifier", ErrFormat)
	}
	return out, nil
}

// IsZero reports whether s is the zero value.
func (s SessionID) IsZero() bool {
	var z [sessionBytes]byte
	return subtle.ConstantTimeCompare(s.b[:], z[:]) == 1
}

// Equal compares in constant time.
func (s SessionID) Equal(o SessionID) bool {
	return subtle.ConstantTimeCompare(s.b[:], o.b[:]) == 1
}

// String returns the text form, or "" for the zero value.
func (s SessionID) String() string {
	if s.IsZero() {
		return ""
	}
	return sessionPrefix + "_" + encode(s.b[:])
}

// GoString keeps %#v from printing the secret.
func (s SessionID) GoString() string { return "id.SessionID{...}" }

// LogValue implements slog.LogValuer so a session ID passed to a logger is
// redacted. Session IDs grant playback and must never appear in logs.
func (s SessionID) LogValue() slog.Value { return slog.StringValue(sessionPrefix + "_[redacted]") }

// MarshalText implements encoding.TextMarshaler. The zero value is an error.
func (s SessionID) MarshalText() ([]byte, error) {
	if s.IsZero() {
		return nil, ErrZeroSession
	}
	return []byte(s.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler using ParseSession.
func (s *SessionID) UnmarshalText(b []byte) error {
	v, err := ParseSession(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}
