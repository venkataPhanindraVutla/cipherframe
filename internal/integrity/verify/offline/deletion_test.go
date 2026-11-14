package offline_test

import (
	"bytes"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/deletion"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline/offlinetest"
)

func deletionEnvelope(t *testing.T, key offlinetest.Key) []byte {
	t.Helper()
	built, err := deletion.Build(offlinetest.DeletionInput())
	if err != nil {
		t.Fatal(err)
	}
	return offlinetest.SignDeletion(t, built.Canonical, key)
}

func TestVerifyDeletion(t *testing.T) {
	a, b := offlinetest.NewKey("sk_a", "a"), offlinetest.NewKey("sk_b", "b")
	keys, err := offline.ParseKeySet(offlinetest.KeySetJSON([]offlinetest.Key{a, b}, map[string]string{"sk_a": "retired", "sk_b": "active"}))
	if err != nil {
		t.Fatal(err)
	}
	env := deletionEnvelope(t, a)

	res, signed := offline.VerifyDeletion(env, keys)
	if res.Outcome != offline.Ours || res.Reason != offline.ReasonVerified || signed == nil {
		t.Fatalf("result = %+v", res)
	}
	r := signed.Record
	if r.ObjectsDeleted != 9 || r.BytesDeleted != 13100 || r.ContentKeys.Destroyed != 2 || r.Reason != "requested" {
		t.Fatalf("record = %+v", r)
	}

	// A key the verifier does not trust: cannot say, never ours.
	other, _ := offline.ParseKeySet(offlinetest.KeySetJSON([]offlinetest.Key{b}, map[string]string{"sk_b": "active"}))
	if res, signed := offline.VerifyDeletion(env, other); res.Outcome != offline.CannotSay || res.Reason != offline.ReasonUntrustedKey || signed != nil {
		t.Fatalf("untrusted key: %+v", res)
	}

	// An altered payload: the signature no longer verifies.
	tampered := bytes.Replace(env, []byte("ZGVsZXRpb24"), []byte("ZGVsZXRpb25"), 1)
	if bytes.Equal(tampered, env) { // the base64 of the payload starts with the same bytes as the schema member
		tampered = bytes.Replace(env, []byte(`"payload":"`), []byte(`"payload":"AA`), 1)
	}
	if res, signed := offline.VerifyDeletion(tampered, keys); res.Outcome != offline.CannotSay || signed != nil {
		t.Fatalf("tampered: %+v", res)
	}

	// A manifest envelope is not a deletion record, even when a trusted key signed it.
	f := offlinetest.New(t)
	manifestEnv := offlinetest.Sign(t, f.Built.Canonical, a)
	if res, signed := offline.VerifyDeletion(manifestEnv, keys); res.Outcome != offline.CannotSay || res.Reason != offline.ReasonMalformed || signed != nil {
		t.Fatalf("manifest as a deletion record: %+v", res)
	}
	// And the other way round.
	if res := offline.VerifyArtifact(env, keys, "master.m3u8", [32]byte{}, "original"); res.Outcome != offline.CannotSay || res.Reason != offline.ReasonMalformed {
		t.Fatalf("deletion record as a manifest: %+v", res)
	}
	// Garbage.
	if res, _ := offline.VerifyDeletion([]byte("nope"), keys); res.Outcome != offline.CannotSay || res.Reason != offline.ReasonMalformed {
		t.Fatalf("garbage: %+v", res)
	}
}
