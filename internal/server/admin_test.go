package server

import "testing"

func TestParseAdminArgs(t *testing.T) {
	c, err := ParseArgs([]string{"admin", "bootstrap", "--tenant-name", "Acme", "--client-name=Main app"})
	if err != nil || c.Admin == nil || c.Admin.Action != AdminBootstrap || c.Admin.TenantName != "Acme" || c.Admin.ClientName != "Main app" {
		t.Fatalf("bootstrap: %+v, %v", c, err)
	}
	c, err = ParseArgs([]string{"admin", "pepper-usage"})
	if err != nil || c.Admin == nil || c.Admin.Action != AdminPepperUsage {
		t.Fatalf("pepper-usage: %+v, %v", c, err)
	}
	for _, args := range [][]string{
		{"admin"},
		{"admin", "nope"},
		{"admin", "bootstrap"},
		{"admin", "bootstrap", "--tenant-name", "a"},
		{"admin", "bootstrap", "--client-name", "a"},
		{"admin", "bootstrap", "--tenant-name", "a", "--client-name", "b", "extra"},
		{"admin", "pepper-usage", "extra"},
	} {
		if c, err := ParseArgs(args); err == nil {
			t.Errorf("ParseArgs(%v) = %+v, want an error", args, c)
		}
	}
}
