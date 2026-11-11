package dsse

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
)

const (
	manifestType = "application/vnd.cipherframe.manifest+json"
	deletionType = "application/vnd.cipherframe.deletion+json"
)

func testKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("test-fixture-dsse-seed-" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func TestPAESpecExample(t *testing.T) {
	// DSSE protocol.md: PAE("http://example.com/HelloWorld", "hello world").
	got := PAE("http://example.com/HelloWorld", []byte("hello world"))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if string(PAE("", nil)) != "DSSEv1 0  0 " {
		t.Fatalf("empty PAE: %q", PAE("", nil))
	}
	// Lengths are byte lengths, not rune counts.
	if string(PAE("é", []byte("€"))) != "DSSEv1 2 é 3 €" {
		t.Fatalf("utf-8 PAE: %q", PAE("é", []byte("€")))
	}
}

// Fixed-seed vector: seed = SHA-256("test-fixture-dsse-seed-1"). The signature was checked with
// an independent implementation (Python cryptography / OpenSSL Ed25519).
const (
	vecPub = "d2d6faaacd4228af537c8d8f3b632f3d7a6cd1f5b19f0b4a2b8f1ab1547664c9"
	vecSig = "93bbcd677b3b244f69591704b9cf68c04181c2f763e93c500e227370100cacb7" +
		"b1196e78b0ecd170716a306cc763ab0a2c4a4517aa1d2165d1cd21e40931a601"
)

func TestFixedVector(t *testing.T) {
	k := testKey("1")
	if hex.EncodeToString(pub(k)) != vecPub {
		t.Fatal("public key vector")
	}
	payload := []byte(`{"hello":"world"}`)
	env, err := Sign(manifestType, payload, SigningKey{KeyID: "k1", Key: k})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(env.Signatures[0].Sig) != vecSig {
		t.Fatalf("signature %x", env.Signatures[0].Sig)
	}
	enc, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"payloadType":"` + manifestType + `","payload":"eyJoZWxsbyI6IndvcmxkIn0=","signatures":[{"keyid":"k1","sig":"` +
		base64.StdEncoding.EncodeToString(mustHex(t, vecSig)) + `"}]}`
	if string(enc) != want {
		t.Fatalf("encoding:\n%s\n%s", enc, want)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify(dec, manifestType, map[string]ed25519.PublicKey{"k1": pub(k)})
	if err != nil || res.RequireAny() != nil || len(res.Verified) != 1 || !bytes.Equal(res.Payload, payload) {
		t.Fatalf("verify: %+v %v", res, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signed(t *testing.T) (*Envelope, map[string]ed25519.PublicKey) {
	t.Helper()
	a, b := testKey("a"), testKey("b")
	env, err := Sign(manifestType, []byte("payload"), SigningKey{"a", a}, SigningKey{"b", b})
	if err != nil {
		t.Fatal(err)
	}
	return env, map[string]ed25519.PublicKey{"a": pub(a), "b": pub(b)}
}

func TestRotationTwoSignatures(t *testing.T) {
	env, keys := signed(t)
	res, err := Verify(env, manifestType, keys)
	if err != nil || len(res.Verified) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	// Only the new key is trusted: still verifies, the old signature is merely unknown.
	res, err = Verify(env, manifestType, map[string]ed25519.PublicKey{"b": keys["b"]})
	if err != nil || res.RequireAny() != nil || len(res.Unknown) != 1 || res.Unknown[0] != "a" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestNegative(t *testing.T) {
	t.Run("wrong payload type", func(t *testing.T) {
		env, keys := signed(t)
		_, err := Verify(env, deletionType, keys)
		if !errors.Is(err, verify.ErrMalformed) {
			t.Fatal(err)
		}
	})
	t.Run("relabelled payload type", func(t *testing.T) {
		env, keys := signed(t)
		env.PayloadType = deletionType // attacker relabels; signature was over the manifest type
		res, err := Verify(env, deletionType, keys)
		if err != nil {
			t.Fatal(err)
		}
		if err := res.RequireAny(); !errors.Is(err, verify.ErrTampered) {
			t.Fatal(err)
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		env, keys := signed(t)
		env.Payload[0] ^= 1
		res, _ := Verify(env, manifestType, keys)
		if err := res.RequireAny(); !errors.Is(err, verify.ErrTampered) || len(res.Failed) != 2 {
			t.Fatalf("%v %+v", err, res)
		}
	})
	t.Run("tampered signature", func(t *testing.T) {
		env, keys := signed(t)
		env.Signatures[0].Sig[10] ^= 1
		res, _ := Verify(env, manifestType, keys)
		if len(res.Failed) != 1 || res.Failed[0] != "a" || len(res.Verified) != 1 || res.RequireAny() != nil {
			t.Fatalf("%+v", res)
		}
		env.Signatures[1].Sig = env.Signatures[1].Sig[:63]
		res, _ = Verify(env, manifestType, keys)
		if err := res.RequireAny(); !errors.Is(err, verify.ErrTampered) {
			t.Fatal(err)
		}
	})
	t.Run("unknown keyid", func(t *testing.T) {
		env, _ := signed(t)
		res, err := Verify(env, manifestType, map[string]ed25519.PublicKey{"zzz": pub(testKey("a"))})
		if err != nil {
			t.Fatal(err)
		}
		if err := res.RequireAny(); !errors.Is(err, verify.ErrUntrustedKey) {
			t.Fatal(err)
		}
	})
	t.Run("right key wrong id", func(t *testing.T) {
		env, _ := signed(t)
		res, _ := Verify(env, manifestType, map[string]ed25519.PublicKey{"a": pub(testKey("other"))})
		if err := res.RequireAny(); !errors.Is(err, verify.ErrTampered) {
			t.Fatal(err)
		}
	})
	t.Run("duplicate keyids", func(t *testing.T) {
		env, keys := signed(t)
		env.Signatures[1].KeyID = "a"
		if _, err := Verify(env, manifestType, keys); !errors.Is(err, verify.ErrMalformed) {
			t.Fatal(err)
		}
	})
	t.Run("empty signatures", func(t *testing.T) {
		env, keys := signed(t)
		env.Signatures = nil
		if _, err := Verify(env, manifestType, keys); !errors.Is(err, verify.ErrMalformed) {
			t.Fatal(err)
		}
	})
	t.Run("missing keyid is untrusted", func(t *testing.T) {
		env, keys := signed(t)
		env.Signatures = []Signature{{Sig: env.Signatures[0].Sig}}
		keys[""] = keys["a"]
		res, err := Verify(env, manifestType, keys)
		if err != nil || res.RequireAny() == nil {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("nil envelope and bad trusted key", func(t *testing.T) {
		env, _ := signed(t)
		if _, err := Verify(nil, manifestType, nil); !errors.Is(err, verify.ErrMalformed) {
			t.Fatal(err)
		}
		_, err := Verify(env, manifestType, map[string]ed25519.PublicKey{"a": {1, 2, 3}})
		if err == nil || verify.Classify(err) != verify.CannotSay {
			t.Fatalf("bad trusted key must be cannot-say, got %v", err)
		}
	})
	t.Run("too many signatures", func(t *testing.T) {
		env, keys := signed(t)
		for i := range MaxSignatures {
			env.Signatures = append(env.Signatures, Signature{KeyID: "x" + string(rune('A'+i)), Sig: make([]byte, 64)})
		}
		if _, err := Verify(env, manifestType, keys); !errors.Is(err, verify.ErrMalformed) {
			t.Fatal(err)
		}
	})
}

type badSigner struct{ crypto.Signer }

func (b badSigner) Sign(_ io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	s, err := b.Signer.Sign(nil, d, o)
	if err == nil {
		s[0] ^= 1
	}
	return s, err
}

func TestSignErrors(t *testing.T) {
	k := testKey("a")
	ok := SigningKey{"a", k}
	cases := map[string]func() error{
		"no signers":  func() error { _, e := Sign(manifestType, nil); return e },
		"empty type":  func() error { _, e := Sign("", nil, ok); return e },
		"empty keyid": func() error { _, e := Sign(manifestType, nil, SigningKey{"", k}); return e },
		"nil key":     func() error { _, e := Sign(manifestType, nil, SigningKey{"a", nil}); return e },
		"duplicate":   func() error { _, e := Sign(manifestType, nil, ok, ok); return e },
		"bad signer":  func() error { _, e := Sign(manifestType, nil, SigningKey{"a", badSigner{k}}); return e },
		"too many": func() error {
			var s []SigningKey
			for i := range MaxSignatures + 1 {
				s = append(s, SigningKey{strings.Repeat("k", i+1), k})
			}
			_, e := Sign(manifestType, nil, s...)
			return e
		},
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// A generic crypto.Signer works (here an ed25519.PrivateKey behind the interface).
	var s crypto.Signer = k
	if _, err := Sign(manifestType, []byte("x"), SigningKey{"a", s}); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeStrict(t *testing.T) {
	sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	p := base64.StdEncoding.EncodeToString([]byte("hi"))
	good := `{"payloadType":"t","payload":"` + p + `","signatures":[{"keyid":"k","sig":"` + sig + `"}]}`
	if _, err := Decode([]byte(good)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"empty":             ``,
		"not object":        `[]`,
		"null":              `null`,
		"unknown top":       `{"payloadType":"t","payload":"","signatures":[],"extra":1}`,
		"wrong case":        `{"PayloadType":"t","payload":"","signatures":[]}`,
		"missing payload":   `{"payloadType":"t","signatures":[]}`,
		"missing type":      `{"payload":"","signatures":[]}`,
		"empty type":        `{"payloadType":"","payload":"","signatures":[]}`,
		"missing sigs":      `{"payloadType":"t","payload":""}`,
		"null sigs":         `{"payloadType":"t","payload":"","signatures":null}`,
		"duplicate member":  `{"payloadType":"t","payloadType":"u","payload":"","signatures":[]}`,
		"escaped duplicate": `{"payloadType":"t","payload":"","signatures":[],"payload":""}`,
		"type not string":   `{"payloadType":1,"payload":"","signatures":[]}`,
		"payload null":      `{"payloadType":"t","payload":null,"signatures":[]}`,
		"bad base64":        `{"payloadType":"t","payload":"!!!","signatures":[]}`,
		"unpadded":          `{"payloadType":"t","payload":"aGk","signatures":[]}`,
		"trailing bits":     `{"payloadType":"t","payload":"aGl=","signatures":[]}`,
		"newline in b64":    `{"payloadType":"t","payload":"aG\nk=","signatures":[]}`,
		"mixed alphabet":    `{"payloadType":"t","payload":"+-/_","signatures":[]}`,
		"sig unknown field": `{"payloadType":"t","payload":"","signatures":[{"sig":"` + sig + `","x":1}]}`,
		"sig missing sig":   `{"payloadType":"t","payload":"","signatures":[{"keyid":"k"}]}`,
		"sig not object":    `{"payloadType":"t","payload":"","signatures":["x"]}`,
		"keyid not string":  `{"payloadType":"t","payload":"","signatures":[{"keyid":1,"sig":"` + sig + `"}]}`,
		"invalid utf8":      "{\"payloadType\":\"\xff\",\"payload\":\"\",\"signatures\":[]}",
		"trailing data":     good + ` {}`,
		"long keyid":        `{"payloadType":"t","payload":"","signatures":[{"keyid":"` + strings.Repeat("k", MaxKeyIDBytes+1) + `","sig":"` + sig + `"}]}`,
		"long type":         `{"payloadType":"` + strings.Repeat("t", MaxPayloadTypeBytes+1) + `","payload":"","signatures":[]}`,
		"too big":           good + strings.Repeat(" ", MaxEnvelopeBytes),
		"too many sigs": `{"payloadType":"t","payload":"","signatures":[` +
			strings.TrimSuffix(strings.Repeat(`{"sig":"`+sig+`"},`, MaxSignatures+1), ",") + `]}`,
	}
	for name, in := range bad {
		if _, err := Decode([]byte(in)); !errors.Is(err, verify.ErrMalformed) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestDecodeAcceptsEitherAlphabetAndOptionalKeyid(t *testing.T) {
	// Bytes 0xfb 0xff encode to "+/8=" (standard) and "-_8=" (URL-safe).
	for _, p := range []string{"+/8=", "-_8="} {
		env, err := Decode([]byte(`{"payloadType":"t","payload":"` + p + `","signatures":[{"sig":"` + p + `"}]}`))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if !bytes.Equal(env.Payload, []byte{0xfb, 0xff}) || !bytes.Equal(env.Signatures[0].Sig, []byte{0xfb, 0xff}) || env.Signatures[0].KeyID != "" {
			t.Fatalf("%s: %+v", p, env)
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	env, keys := signed(t)
	enc, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify(dec, manifestType, keys)
	if err != nil || len(res.Verified) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	// A second "signatures" member injected into an otherwise valid envelope is rejected.
	spaced := strings.Replace(string(enc), `{"payloadType"`, "{ \n\"signatures\": [], \"payloadType\"", 1)
	if _, err := Decode([]byte(spaced)); err == nil {
		t.Fatal("duplicate signatures member must fail")
	}
}

func FuzzDSSEDecode(f *testing.F) {
	env, _ := func() (*Envelope, error) {
		return Sign(manifestType, []byte("seed"), SigningKey{"a", testKey("a")})
	}()
	enc, _ := env.Encode()
	f.Add(enc)
	f.Add([]byte(`{"payloadType":"t","payload":"","signatures":[]}`))
	f.Add([]byte(`{"payloadType":"t","payload":"+/8=","signatures":[{"sig":"-_8="}]}`))
	f.Add([]byte(`{"payloadType":"t","payload":"","payload":""}`))
	f.Add([]byte(``))
	keys := map[string]ed25519.PublicKey{"a": pub(testKey("a"))}
	f.Fuzz(func(t *testing.T, in []byte) {
		e, err := Decode(in)
		if err != nil {
			if verify.Classify(err) != verify.Malformed {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		// Whatever decodes must re-encode, decode to the same envelope, and verify without panic.
		re, err := e.Encode()
		if err != nil {
			t.Fatal(err)
		}
		e2, err := Decode(re)
		if err != nil || e2.PayloadType != e.PayloadType || !bytes.Equal(e2.Payload, e.Payload) || len(e2.Signatures) != len(e.Signatures) {
			t.Fatalf("round trip: %v", err)
		}
		_, _ = Verify(e, e.PayloadType, keys)
	})
}
