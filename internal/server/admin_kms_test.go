package server

import (
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

func TestParseAdminKMSArgs(t *testing.T) {
	c, err := ParseArgs([]string{"admin", "kms-usage"})
	if err != nil || c.Admin == nil || c.Admin.Action != AdminKMSUsage {
		t.Fatalf("kms-usage: %+v, %v", c, err)
	}
	c, err = ParseArgs([]string{"admin", "kms-rewrap"})
	if err != nil || c.Admin == nil || c.Admin.Action != AdminKMSRewrap || c.Admin.Wait || c.Admin.BatchSize != 0 {
		t.Fatalf("kms-rewrap: %+v, %v", c, err)
	}
	c, err = ParseArgs([]string{"admin", "kms-rewrap", "--wait", "--batch-size=25"})
	if err != nil || !c.Admin.Wait || c.Admin.BatchSize != 25 {
		t.Fatalf("kms-rewrap flags: %+v, %v", c, err)
	}
	for _, args := range [][]string{
		{"admin", "kms-usage", "extra"},
		{"admin", "kms-rewrap", "extra"},
		{"admin", "kms-rewrap", "--batch-size=-1"},
		{"admin", "kms-rewrap", "--batch-size=1001"},
		{"admin", "kms-rewrap", "--nope"},
	} {
		if c, err := ParseArgs(args); err == nil {
			t.Errorf("ParseArgs(%v) = %+v, want an error", args, c)
		}
	}
}

func TestKMSUsageLines(t *testing.T) {
	if got := KMSUsageLines(nil); len(got) != 1 || got[0] != "no content keys" {
		t.Fatalf("empty usage = %v", got)
	}
	got := KMSUsageLines([]db.KEKUsage{
		{KEK: db.KEKRef{Provider: "local", KeyID: "local", Version: "1"}, Keys: 4},
		{KEK: db.KEKRef{Provider: "vault", KeyID: "cipherframe", Version: "3"}, Keys: 9},
	})
	want := []string{
		"provider=local kek_id=local version=1: 4 content keys",
		"provider=vault kek_id=cipherframe version=3: 9 content keys",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v, want %v", got, want)
	}
}
