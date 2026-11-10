package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestCredentialStates(t *testing.T) {
	tests := []struct {
		name string
		c    Credential
		want CredentialState
		str  string
	}{
		{"zero is unset", Credential{}, Unset, "unset"},
		{"empty is provider chain", NewStaticCredential(""), ProviderChain, "provider_chain"},
		{"value is static", NewStaticCredential("AKIAdistinctive"), Static, "static"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.c.State() != tc.want || tc.c.String() != tc.str {
				t.Fatalf("state = %v, want %v", tc.c.State(), tc.want)
			}
			for _, o := range []string{fmt.Sprintf("%v", tc.c), fmt.Sprintf("%#v", tc.c), fmt.Sprintf("%+v", struct{ C Credential }{tc.c})} {
				if strings.Contains(o, "AKIAdistinctive") {
					t.Fatal("credential value leaked")
				}
			}
		})
	}
	if NewStaticCredential("v").Secret().Reveal() != "v" {
		t.Fatal("static value lost")
	}
}
