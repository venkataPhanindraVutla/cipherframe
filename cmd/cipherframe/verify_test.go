package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/proof"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline/offlinetest"
)

type env struct {
	f        *offlinetest.Fixture
	manifest string
	keys     string
	keysJSON []byte
	dir      string
}

func setup(t *testing.T) env {
	t.Helper()
	e := env{f: offlinetest.New(t), dir: t.TempDir()}
	a, b := offlinetest.NewKey("sk_a", "a"), offlinetest.NewKey("sk_b", "b")
	// Signed by A; the published set has A retired and B active (public keys only).
	e.keysJSON = offlinetest.KeySetJSON([]offlinetest.Key{a, b}, map[string]string{"sk_a": "retired", "sk_b": "active"})
	e.manifest = write(t, e.dir, "m.json", offlinetest.Sign(t, e.f.Built.Canonical, a))
	e.keys = write(t, e.dir, "keys.json", e.keysJSON)
	return e
}

func write(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil { //nolint:gosec // test fixture path
		t.Fatal(err)
	}
	return p
}

func do(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVerifyDirectoryOurs(t *testing.T) {
	e := setup(t)
	code, out, _ := do("verify", "--manifest", e.manifest, "--keys", e.keys, e.f.Original)
	if code != 0 || !strings.Contains(out, "10 ours, 0 modified, 0 cannot say, 0 missing") {
		t.Fatalf("code %d\n%s", code, out)
	}
	if !strings.Contains(out, "ours        720p/seg-1.m4s  (verified)") {
		t.Fatalf("line format:\n%s", out)
	}
}

func TestFlippedByteNamesTheExactPath(t *testing.T) {
	e := setup(t)
	seg := filepath.Join(e.f.Original, "480p", "seg-1.m4s")
	b, _ := os.ReadFile(seg) //nolint:gosec // test fixture path
	b[0] ^= 1
	write(t, filepath.Dir(seg), "seg-1.m4s", b)
	code, out, _ := do("verify", "--manifest", e.manifest, "--keys", e.keys, e.f.Original)
	if code != 1 || !strings.Contains(out, "modified    480p/seg-1.m4s") || !strings.Contains(out, "1 modified") {
		t.Fatalf("code %d\n%s", code, out)
	}
	if strings.Count(out, "modified ") != 1 {
		t.Fatalf("only that file may be modified:\n%s", out)
	}
	// JSON.
	code, out, _ = do("verify", "--json", "--manifest", e.manifest, "--keys", e.keys, e.f.Original)
	var doc struct {
		Results []struct{ Path, Outcome, Reason string }
		Summary map[string]int
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 1 || doc.Summary["modified"] != 1 {
		t.Fatalf("json: %v code %d\n%s", err, code, out)
	}
}

func TestMissingIsNotModified(t *testing.T) {
	e := setup(t)
	if err := os.Remove(filepath.Join(e.f.Original, "master.m3u8")); err != nil {
		t.Fatal(err)
	}
	code, out, _ := do("verify", "--manifest", e.manifest, "--keys", e.keys, e.f.Original)
	if code != 2 || !strings.Contains(out, "missing     master.m3u8") || strings.Contains(out, "modified    ") {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestMaskedVariant(t *testing.T) {
	e := setup(t)
	code, out, _ := do("verify", "--variant", "masked", "--manifest", e.manifest, "--keys", e.keys, e.f.Masked)
	if code != 0 || !strings.Contains(out, "10 ours") {
		t.Fatalf("masked: code %d\n%s", code, out)
	}
	// The masked tree checked as the original is modified, not accepted.
	if code, _, _ = do("verify", "--manifest", e.manifest, "--keys", e.keys, e.f.Masked); code != 1 {
		t.Fatalf("masked as original: code %d", code)
	}
}

func TestSingleFileByPathAndRoot(t *testing.T) {
	e := setup(t)
	f := filepath.Join(e.f.Original, "720p", "init.mp4")
	for _, args := range [][]string{
		{"--path", "720p/init.mp4", f},
		{"--root", e.f.Original, f},
	} {
		code, out, _ := do(append([]string{"verify", "--manifest", e.manifest, "--keys", e.keys}, args...)...)
		if code != 0 || !strings.Contains(out, "1 ours") {
			t.Fatalf("%v: code %d\n%s", args, code, out)
		}
	}
	// Unknown path: cannot say.
	code, out, _ := do("verify", "--manifest", e.manifest, "--keys", e.keys, "--path", "nope/x.m4s", f)
	if code != 2 || !strings.Contains(out, "unknown-path") {
		t.Fatalf("unknown path: code %d\n%s", code, out)
	}
}

func TestCannotSayNeverModified(t *testing.T) {
	e := setup(t)
	f := filepath.Join(e.f.Original, "master.m3u8")
	b, _ := os.ReadFile(f) //nolint:gosec // test fixture path
	b[0] ^= 1              // a changed file, so any wrong "modified" would show
	write(t, filepath.Dir(f), "master.m3u8", b)

	other := offlinetest.KeySetJSON([]offlinetest.Key{offlinetest.NewKey("sk_z", "z")}, map[string]string{"sk_z": "active"})
	forged := write(t, e.dir, "forged.json", offlinetest.Sign(t, e.f.Built.Canonical, offlinetest.NewKey("sk_a", "forger")))
	cases := map[string][]string{
		"unknown key":          {"--manifest", e.manifest, "--keys", write(t, e.dir, "other.json", other)},
		"malformed envelope":   {"--manifest", write(t, e.dir, "bad.json", []byte("{")), "--keys", e.keys},
		"tampered envelope":    {"--manifest", forged, "--keys", e.keys},
		"missing manifest":     {"--manifest", filepath.Join(e.dir, "none.json"), "--keys", e.keys},
		"missing keys file":    {"--manifest", e.manifest, "--keys", filepath.Join(e.dir, "none.json")},
		"malformed key set":    {"--manifest", e.manifest, "--keys", write(t, e.dir, "k2.json", []byte("[]"))},
		"keys-url unreachable": {"--manifest", e.manifest, "--keys-url", "http://127.0.0.1:1/keys.json"},
	}
	for name, a := range cases {
		code, out, _ := do(append(append([]string{"verify"}, a...), "--path", "master.m3u8", f)...)
		if code != 2 || strings.Contains(out, "modified    ") || !strings.Contains(out, "cannot say") {
			t.Errorf("%s: code %d\n%s", name, code, out)
		}
	}
	code, out, _ := do("verify", "--manifest", e.manifest, "--keys", e.keys, "--path", "master.m3u8", f)
	if code != 1 {
		t.Fatalf("control: a changed file under a good signature is modified, got %d\n%s", code, out)
	}
}

func TestKeysURL(t *testing.T) {
	e := setup(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/keys.json":
			_, _ = w.Write(e.keysJSON)
		case "/huge":
			_, _ = w.Write(bytes.Repeat([]byte(" "), 2<<20))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	args := []string{"verify", "--manifest", e.manifest, e.f.Original}
	if code, out, _ := do(append(args[:3:3], "--keys-url", srv.URL+"/keys.json", e.f.Original)...); code != 0 {
		t.Fatalf("code %d\n%s", code, out)
	}
	for _, p := range []string{"/missing", "/huge"} {
		if code, _, _ := do(append(args[:3:3], "--keys-url", srv.URL+p, e.f.Original)...); code != 2 {
			t.Errorf("%s: code %d, want 2", p, code)
		}
	}
	// Plain http to a non-loopback host is a usage error.
	if code, _, _ := do("verify", "--manifest", e.manifest, "--keys-url", "http://example.com/k.json", e.f.Original); code != 3 {
		t.Errorf("http to a remote host: code %d, want 3", code)
	}
}

func TestProofMode(t *testing.T) {
	e := setup(t)
	pr, err := proof.Build(e.f.Built.Manifest, "masked", "720p/seg-2.m4s")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(pr)
	pf := write(t, e.dir, "p.json", b)
	file := filepath.Join(e.f.Masked, "720p", "seg-2.m4s")
	code, out, _ := do("verify", "--manifest", e.manifest, "--keys", e.keys, "--proof", pf, file)
	if code != 0 || !strings.Contains(out, "ours        720p/seg-2.m4s") {
		t.Fatalf("code %d\n%s", code, out)
	}
	// The original's file at the same path is another hash: modified.
	other := filepath.Join(e.f.Original, "720p", "seg-2.m4s")
	if code, _, _ = do("verify", "--manifest", e.manifest, "--keys", e.keys, "--proof", pf, other); code != 1 {
		t.Errorf("other file: code %d", code)
	}
	if code, _, _ = do("verify", "--manifest", e.manifest, "--keys", e.keys, "--proof", write(t, e.dir, "p2.json", []byte("{")), file); code != 2 {
		t.Errorf("malformed proof: code %d", code)
	}
}

func TestUsageAndHelp(t *testing.T) {
	e := setup(t)
	for name, args := range map[string][]string{
		"no command":     {},
		"unknown":        {"frob"},
		"no files":       {"verify", "--manifest", e.manifest, "--keys", e.keys},
		"no keys":        {"verify", "--manifest", e.manifest, e.f.Original},
		"both keys":      {"verify", "--manifest", e.manifest, "--keys", e.keys, "--keys-url", "https://x/", e.f.Original},
		"bad variant":    {"verify", "--manifest", e.manifest, "--keys", e.keys, "--variant", "x", e.f.Original},
		"bad flag":       {"verify", "--nope"},
		"path two files": {"verify", "--manifest", e.manifest, "--keys", e.keys, "--path", "a", "x", "y"},
	} {
		if code, _, _ := do(args...); code != 3 {
			t.Errorf("%s: code %d, want 3", name, code)
		}
	}
	if code, out, _ := do("version"); code != 0 || !strings.HasPrefix(out, "cipherframe ") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, out, _ := do("help"); code != 0 || !strings.Contains(out, "cipherframe verify") {
		t.Errorf("help: %d %q", code, out)
	}
}
