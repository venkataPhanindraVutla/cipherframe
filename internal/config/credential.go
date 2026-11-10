package config

import (
	"fmt"
	"log/slog"
)

// CredentialState is the three-state meaning of a credential variable.
type CredentialState int

const (
	// Unset means the variable is absent.
	Unset CredentialState = iota
	// ProviderChain means the variable is present but empty: use the cloud SDK's
	// default credential chain (for example an instance role).
	ProviderChain
	// Static means the variable holds a value.
	Static
)

// String returns "unset", "provider_chain" or "static".
func (s CredentialState) String() string {
	switch s {
	case Unset:
		return "unset"
	case ProviderChain:
		return "provider_chain"
	case Static:
		return "static"
	default:
		return "invalid"
	}
}

// Credential is a three-state credential. The states are never collapsed.
type Credential struct {
	state CredentialState
	value Secret
}

// NewStaticCredential returns a Static credential holding v. An empty v yields
// a ProviderChain credential, matching how the loader reads an empty variable.
func NewStaticCredential(v string) Credential {
	if v == "" {
		return Credential{state: ProviderChain}
	}
	return Credential{state: Static, value: NewSecret(v)}
}

// State returns the credential's state.
func (c Credential) State() CredentialState { return c.state }

// Secret returns the static value; it is empty unless State is Static.
func (c Credential) Secret() Secret { return c.value }

// String returns the state name, never the value.
func (c Credential) String() string { return c.state.String() }

// GoString implements fmt.GoStringer.
func (c Credential) GoString() string { return "config.Credential(" + c.state.String() + ")" }

// Format implements fmt.Formatter. It prints only the state.
func (c Credential) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(c.state.String())) }

// MarshalText implements encoding.TextMarshaler.
func (c Credential) MarshalText() ([]byte, error) { return []byte(c.state.String()), nil }

// MarshalJSON implements json.Marshaler.
func (c Credential) MarshalJSON() ([]byte, error) { return []byte(`"` + c.state.String() + `"`), nil }

// LogValue implements slog.LogValuer.
func (c Credential) LogValue() slog.Value { return slog.StringValue(c.state.String()) }
