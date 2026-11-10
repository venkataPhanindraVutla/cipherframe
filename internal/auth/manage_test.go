package auth

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

func TestValidateName(t *testing.T) {
	for _, s := range []string{"a", "My app", strings.Repeat("é", 100), "日本語"} {
		if err := ValidateName(s); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
	for _, s := range []string{"", " ", "\t", strings.Repeat("a", 101), "a\nb", "a\x00b", "\xff"} {
		wantCode(t, ValidateName(s), errs.InvalidRequest)
	}
}

func TestResolveScopes(t *testing.T) {
	def, err := ResolveScopes(nil)
	if err != nil || slices.Contains(def, db.ScopeAdmin) || len(def) != 4 {
		t.Fatalf("default scopes = %v, %v", def, err)
	}
	got, err := ResolveScopes([]db.Scope{db.ScopeAdmin})
	if err != nil || len(got) != 1 {
		t.Fatalf("explicit admin: %v %v", got, err)
	}
	for _, in := range [][]db.Scope{{}, {"nope"}, {db.ScopeAdmin, db.ScopeAdmin}} {
		_, err := ResolveScopes(in)
		wantCode(t, err, errs.InvalidRequest)
	}
	if len(AllScopes()) != 5 {
		t.Fatal("expected five scopes")
	}
}

func TestCheckPeppers(t *testing.T) {
	c := counter{1: 3, 7: 1, 4: 2}
	err := CheckPeppers(context.Background(), c, peppers(), t0)
	if err == nil || !strings.Contains(err.Error(), "4, 7") {
		t.Fatalf("error = %v, want versions 4, 7 named", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("a", 32)) {
		t.Fatal("pepper value in the error")
	}
	if err := CheckPeppers(context.Background(), counter{1: 3, 2: 1}, peppers(), t0); err != nil {
		t.Fatal(err)
	}
}

type counter map[int]int64

func (c counter) CountAPIKeysByPepperVersion(context.Context, time.Time) (map[int]int64, error) {
	return c, nil
}

func TestPepperUsageLines(t *testing.T) {
	got := PepperUsageLines(map[int]int64{1: 4, 3: 2}, []int{1, 2}, 2)
	want := []string{
		"version 1: 4 active keys",
		"version 2: 0 active keys (current)",
		"version 3: 2 active keys (NOT CONFIGURED)",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}
