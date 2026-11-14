package offline_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/proof"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline/offlinetest"
)

func sumOf(t *testing.T, dir, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p))) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func setup(t *testing.T) (f *offlinetest.Fixture, env []byte, keys offline.KeySet) {
	t.Helper()
	f = offlinetest.New(t)
	a := offlinetest.NewKey("sk_a", "a")
	env = offlinetest.Sign(t, f.Built.Canonical, a)
	keys, err := offline.ParseKeySet(offlinetest.KeySetJSON([]offlinetest.Key{a}, map[string]string{"sk_a": "active"}))
	if err != nil {
		t.Fatal(err)
	}
	return f, env, keys
}

func TestOursAndModifiedNamesTheOutcome(t *testing.T) {
	f, env, keys := setup(t)
	for _, p := range f.Files["original"] {
		if r := offline.VerifyArtifact(env, keys, p, sumOf(t, f.Original, p), "original"); r.Outcome != offline.Ours {
			t.Fatalf("%s: %+v", p, r)
		}
	}
	bad := sumOf(t, f.Original, "720p/seg-1.m4s")
	bad[0] ^= 1
	r := offline.VerifyArtifact(env, keys, "720p/seg-1.m4s", bad, "original")
	if r.Outcome != offline.Modified || r.Reason != offline.ReasonModified {
		t.Fatalf("flipped hash: %+v", r)
	}
	for _, p := range f.Files["masked"] {
		if r := offline.VerifyArtifact(env, keys, p, sumOf(t, f.Masked, p), "masked"); r.Outcome != offline.Ours {
			t.Fatalf("masked %s: %+v", p, r)
		}
	}
	// The masked file is not the original's file.
	if r := offline.VerifyArtifact(env, keys, "master.m3u8", sumOf(t, f.Masked, "master.m3u8"), "original"); r.Outcome != offline.Modified {
		t.Fatalf("masked file as original: %+v", r)
	}
}

func TestNeverModifiedWithoutAValidTrustedSignature(t *testing.T) {
	f, env, keys := setup(t)
	sum := sumOf(t, f.Original, "master.m3u8")
	sum[3] ^= 1 // a wrong hash: it must still not read as modified

	other := offlinetest.NewKey("sk_other", "other")
	otherKeys, _ := offline.ParseKeySet(offlinetest.KeySetJSON([]offlinetest.Key{other}, map[string]string{"sk_other": "active"}))

	// Same keyid, different key: a trusted key id whose signature does not verify.
	forged := offlinetest.NewKey("sk_a", "forger")
	forgedEnv := offlinetest.Sign(t, f.Built.Canonical, forged)

	// Valid signature, but the payload is not a manifest.
	notManifest := offlinetest.Sign(t, []byte(`{"schema":"other"}`), offlinetest.NewKey("sk_a", "a"))

	cases := []struct {
		name   string
		env    []byte
		keys   offline.KeySet
		reason offline.Reason
	}{
		{"unknown key", env, otherKeys, offline.ReasonUntrustedKey},
		{"empty key set", env, offline.KeySet{}, offline.ReasonUntrustedKey},
		{"bad signature by a trusted key id", forgedEnv, keys, offline.ReasonTamperedEnvelope},
		{"malformed envelope", []byte(`{"payload":`), keys, offline.ReasonMalformed},
		{"empty envelope", nil, keys, offline.ReasonMalformed},
		{"not a manifest", notManifest, keys, offline.ReasonMalformed},
	}
	for _, tc := range cases {
		r := offline.VerifyArtifact(tc.env, tc.keys, "master.m3u8", sum, "original")
		if r.Outcome != offline.CannotSay || r.Reason != tc.reason {
			t.Errorf("%s: %+v, want cannot say / %s", tc.name, r, tc.reason)
		}
	}
	if r := offline.VerifyArtifact(env, keys, "nope/seg.m4s", sum, "original"); r.Outcome != offline.CannotSay || r.Reason != offline.ReasonUnknownPath {
		t.Errorf("unknown path: %+v", r)
	}
	if r := offline.VerifyArtifact(env, keys, "master.m3u8", sum, "bogus"); r.Outcome != offline.CannotSay {
		t.Errorf("unknown variant: %+v", r)
	}
}

func TestRotatedKeyStillVerifiesOldRecords(t *testing.T) {
	f := offlinetest.New(t)
	a, b := offlinetest.NewKey("sk_a", "a"), offlinetest.NewKey("sk_b", "b")
	oldEnv := offlinetest.Sign(t, f.Built.Canonical, a)
	newEnv := offlinetest.Sign(t, f.Built.Canonical, b)
	// The published set after rotating to B and retiring A: public keys only.
	keys, err := offline.ParseKeySet(offlinetest.KeySetJSON([]offlinetest.Key{a, b}, map[string]string{"sk_a": "retired", "sk_b": "active"}))
	if err != nil {
		t.Fatal(err)
	}
	sum := sumOf(t, f.Original, "720p/init.mp4")
	for name, env := range map[string][]byte{"old": oldEnv, "new": newEnv} {
		if r := offline.VerifyArtifact(env, keys, "720p/init.mp4", sum, "original"); r.Outcome != offline.Ours {
			t.Errorf("%s record: %+v", name, r)
		}
	}
}

func TestParseKeySet(t *testing.T) {
	a := offlinetest.NewKey("sk_a", "a")
	ks, err := offline.ParseKeySet(offlinetest.KeySetJSON([]offlinetest.Key{a}, map[string]string{"sk_a": "revoked"}))
	if err != nil || len(ks) != 0 {
		t.Errorf("an unknown status must not be trusted: %v %v", ks, err)
	}
	for _, bad := range []string{
		``, `{}`, `{"keys":[{"keyid":"","alg":"ed25519"}]}`,
		`{"keys":[{"keyid":"x","alg":"ed25519","status":"active","public_key":"AAAA"}]}`,
	} {
		if _, err := offline.ParseKeySet([]byte(bad)); !errors.Is(err, verify.ErrMalformed) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestProofs(t *testing.T) {
	f, env, keys := setup(t)
	for variant, dir := range map[string]string{"original": f.Original, "masked": f.Masked} {
		for _, p := range f.Files[variant] {
			pr, err := proof.Build(f.Built.Manifest, variant, p)
			if err != nil {
				t.Fatal(err)
			}
			if r := offline.VerifyProof(env, keys, *pr, sumOf(t, dir, p)); r.Outcome != offline.Ours {
				t.Fatalf("%s %s: %+v", variant, p, r)
			}
		}
	}
	pr, _ := proof.Build(f.Built.Manifest, "original", "720p/seg-2.m4s")
	sum := sumOf(t, f.Original, "720p/seg-2.m4s")
	sum[9] ^= 1
	if r := offline.VerifyProof(env, keys, *pr, sum); r.Outcome != offline.Modified {
		t.Errorf("flipped byte: %+v", r)
	}
	// A proof with a broken audit path or from another manifest is a bad proof, not a modified file.
	good := sumOf(t, f.Original, "720p/seg-2.m4s")
	var broken proof.Proof
	b, _ := json.Marshal(pr)
	_ = json.Unmarshal(b, &broken)
	broken.AuditPath = append([]string{}, broken.AuditPath...)
	broken.AuditPath[0] = pr.TopLevel.Root
	if r := offline.VerifyProof(env, keys, broken, good); r.Outcome != offline.CannotSay {
		t.Errorf("broken audit path: %+v", r)
	}
	foreign := *pr
	foreign.TopLevel.Root = pr.RenditionRoot
	if r := offline.VerifyProof(env, keys, foreign, good); r.Outcome != offline.CannotSay || r.Reason != offline.ReasonMalformed {
		t.Errorf("foreign proof: %+v", r)
	}
	unknown := *pr
	unknown.Path = "nope"
	if r := offline.VerifyProof(env, keys, unknown, good); r.Outcome != offline.CannotSay {
		t.Errorf("unknown path: %+v", r)
	}
}
