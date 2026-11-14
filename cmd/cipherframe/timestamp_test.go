package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/timestamp"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/timestamp/tsatest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
)

// stamp asks the test authority for a token over the manifest payload of e and writes the
// timestamp document and the authority's CA bundle next to the manifest.
func stamp(t *testing.T, e env, a *tsatest.TSA, payload []byte) (tsFile, caFile string) {
	t.Helper()
	nonce, _ := timestamp.NewNonce()
	req, err := timestamp.BuildRequest(timestamp.Digest(payload), nonce, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Respond(req, tsatest.Grant)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := timestamp.ParseResponse(resp, timestamp.Digest(payload), nonce)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(offline.TimestampDoc{
		Token: base64.StdEncoding.EncodeToString(tok.DER), GenTime: tok.GenTime, TSAURL: "https://tsa.test-fixture.example/tsr",
		ImprintSHA256: "00",
	})
	return write(t, e.dir, "ts.json", doc), write(t, e.dir, "ca.pem", a.RootPEM)
}

func TestTimestampAnchored(t *testing.T) {
	e := setup(t)
	a := tsatest.New(t)
	ts, ca := stamp(t, e, a, e.f.Built.Canonical)
	code, out, _ := do("verify", "--manifest", e.manifest, "--keys", e.keys, "--timestamp", ts, "--tsa-ca", ca, e.f.Original)
	if code != 0 || !strings.Contains(out, "10 ours") {
		t.Fatalf("code %d\n%s", code, out)
	}
	last := strings.Split(strings.TrimSpace(out), "\n")
	if got := last[len(last)-1]; !strings.HasPrefix(got, "anchored  20") || !strings.HasSuffix(got, "  (https://tsa.test-fixture.example/tsr)") {
		t.Fatalf("anchored line = %q", got)
	}
	code, out, _ = do("verify", "--json", "--manifest", e.manifest, "--keys", e.keys, "--timestamp", ts, "--tsa-ca", ca, e.f.Original)
	var res struct {
		Timestamp tsStatus `json:"timestamp"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || code != 0 || res.Timestamp.Status != tsAnchored {
		t.Fatalf("json: code %d %v %s", code, err, out)
	}
}

func TestTimestampInvalidIsCannotSayNotModified(t *testing.T) {
	e := setup(t)
	a := tsatest.New(t)
	ts, ca := stamp(t, e, a, e.f.Built.Canonical)
	other := write(t, e.dir, "other-ca.pem", tsatest.New(t).RootPEM)
	// The stamp is for another payload: the manifest on disk is the signed one, the token is not its.
	wrongTS, _ := stamp(t, e, a, []byte("test-fixture-another-manifest"))

	for name, args := range map[string][]string{
		"untrusted CA":  {"--timestamp", ts, "--tsa-ca", other},
		"wrong imprint": {"--timestamp", wrongTS, "--tsa-ca", ca},
		"missing file":  {"--timestamp", e.dir + "/nope.json", "--tsa-ca", ca},
		"not a doc":     {"--timestamp", write(t, e.dir, "junk.json", []byte("test-fixture-junk")), "--tsa-ca", ca},
		"system roots":  {"--timestamp", ts}, // the test CA is not a system root
	} {
		full := append([]string{"verify", "--manifest", e.manifest, "--keys", e.keys}, args...)
		code, out, _ := do(append(full, e.f.Original)...)
		if code != 2 || !strings.Contains(out, "timestamp invalid (") || strings.Contains(out, "modified  ") {
			t.Errorf("%s: code %d\n%s", name, code, out)
		}
	}
}

func TestTimestampUnanchoredAndAbsent(t *testing.T) {
	e := setup(t)
	problem := write(t, e.dir, "problem.json", []byte(`{"code":"not_anchored","status":404}`))
	code, out, _ := do("verify", "--manifest", e.manifest, "--keys", e.keys, "--timestamp", problem, e.f.Original)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || lines[len(lines)-1] != "unanchored" {
		t.Fatalf("unanchored: code %d\n%s", code, out)
	}
	empty := write(t, e.dir, "empty.json", nil)
	if code, out, _ = do("verify", "--manifest", e.manifest, "--keys", e.keys, "--timestamp", empty, e.f.Original); code != 0 || !strings.HasSuffix(strings.TrimSpace(out), "unanchored") {
		t.Fatalf("empty: code %d\n%s", code, out)
	}

	// Without --timestamp nothing about anchoring is printed and the exit code is unchanged.
	code, out, _ = do("verify", "--manifest", e.manifest, "--keys", e.keys, e.f.Original)
	if code != 0 || strings.Contains(out, "anchored") || strings.Contains(out, "timestamp") {
		t.Fatalf("absent: code %d\n%s", code, out)
	}
	if code, _, _ := do("verify", "--manifest", e.manifest, "--keys", e.keys, "--tsa-ca", "x.pem", e.f.Original); code != 3 {
		t.Errorf("--tsa-ca alone: code %d, want 3", code)
	}
}

func TestTimestampWithModifiedFileStaysModified(t *testing.T) {
	e := setup(t)
	a := tsatest.New(t)
	ts, ca := stamp(t, e, a, e.f.Built.Canonical)
	seg := filepath.Join(e.f.Original, "480p", "seg-1.m4s")
	b, _ := os.ReadFile(seg) //nolint:gosec // test fixture path
	b[0] ^= 1
	write(t, filepath.Dir(seg), "seg-1.m4s", b)
	code, out, _ := do("verify", "--manifest", e.manifest, "--keys", e.keys, "--timestamp", ts, "--tsa-ca", ca, e.f.Original)
	if code != 1 || !strings.Contains(out, "anchored  ") {
		t.Fatalf("code %d\n%s", code, out)
	}
}
