package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/deletion"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline/offlinetest"
)

func TestVerifyDeletionRecord(t *testing.T) {
	e := setup(t)
	built, err := deletion.Build(offlinetest.DeletionInput())
	if err != nil {
		t.Fatal(err)
	}
	rec := write(t, e.dir, "r.json", offlinetest.SignDeletion(t, built.Canonical, offlinetest.NewKey("sk_a", "a")))

	code, out, _ := do("verify", "--deletion-record", rec, "--keys", e.keys)
	if code != 0 {
		t.Fatalf("code %d\n%s", code, out)
	}
	for _, want := range []string{
		"ours        deletion record  (verified)", "asset ast_00000000000000000000000001", "deleted 9 objects, 13100 bytes",
		"delivery  segment   masked", "content keys destroyed: 2", "cky_00000000000000000000000002 (masked)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	code, out, _ = do("verify", "--json", "--deletion-record", rec, "--keys", e.keys)
	var doc struct {
		Outcome, Reason string
		Record          struct {
			ObjectsDeleted int `json:"objects_deleted"`
		}
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 0 || doc.Outcome != "ours" || doc.Record.ObjectsDeleted != 9 {
		t.Fatalf("json: %v code %d\n%s", err, code, out)
	}

	// Signed by a key that is not in the set: cannot say, exit 2, and the contents are not shown.
	stranger := write(t, e.dir, "s.json", offlinetest.SignDeletion(t, built.Canonical, offlinetest.NewKey("sk_z", "z")))
	code, out, _ = do("verify", "--deletion-record", stranger, "--keys", e.keys)
	if code != 2 || !strings.Contains(out, "cannot say") || strings.Contains(out, "asset ast_") {
		t.Fatalf("untrusted: code %d\n%s", code, out)
	}
	// A missing file is cannot say too, never ours.
	if code, _, _ = do("verify", "--deletion-record", e.dir+"/nope.json", "--keys", e.keys); code != 2 {
		t.Fatalf("missing file: code %d", code)
	}
	// The record flag stands alone.
	for _, args := range [][]string{
		{"--deletion-record", rec, "--keys", e.keys, "--manifest", e.manifest},
		{"--deletion-record", rec, "--keys", e.keys, "somefile"},
		{"--deletion-record", rec},
	} {
		if code, _, _ = do(append([]string{"verify"}, args...)...); code != 3 {
			t.Errorf("%v: code %d, want 3", args, code)
		}
	}
}
