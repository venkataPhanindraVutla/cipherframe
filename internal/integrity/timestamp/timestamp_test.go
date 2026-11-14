package timestamp_test

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	dt "github.com/digitorus/timestamp"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/timestamp"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/timestamp/tsatest"
)

var payload = []byte(`{"schema":"test-fixture-manifest"}`)

func TestBuildRequest(t *testing.T) {
	digest := timestamp.Digest(payload)
	nonce, err := timestamp.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	policy := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	der, err := timestamp.BuildRequest(digest, nonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	req, err := dt.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if string(req.HashedMessage) != string(digest[:]) || req.Nonce.Cmp(nonce) != 0 || !req.Certificates || !req.TSAPolicyOID.Equal(policy) {
		t.Fatalf("request does not carry the digest, nonce, certReq and policy: %+v", req)
	}
	if _, err := timestamp.BuildRequest(digest, nil, nil); err == nil {
		t.Fatal("a request without a nonce was built")
	}
}

func TestParseResponse(t *testing.T) {
	a := tsatest.New(t)
	digest := timestamp.Digest(payload)
	other := timestamp.Digest([]byte("test-fixture-other"))
	cases := []struct {
		name   string
		mode   tsatest.Mode
		digest [32]byte // the digest the verifier expects
		want   error
	}{
		{"granted", tsatest.Grant, digest, nil},
		{"wrong imprint", tsatest.WrongImprint, digest, timestamp.ErrImprint},
		{"token for another manifest", tsatest.Grant, other, timestamp.ErrImprint},
		{"wrong nonce", tsatest.WrongNonce, digest, timestamp.ErrNonce},
		{"rejected", tsatest.Reject, digest, timestamp.ErrInvalid},
		{"garbage", tsatest.Garbage, digest, timestamp.ErrInvalid},
		{"no certificate", tsatest.NoCertificate, digest, timestamp.ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nonce, _ := timestamp.NewNonce()
			req, err := timestamp.BuildRequest(digest, nonce, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := a.Respond(req, tc.mode)
			if err != nil {
				t.Fatal(err)
			}
			tok, err := timestamp.ParseResponse(resp, tc.digest, nonce)
			if tc.want == nil {
				if err != nil || tok.GenTime.IsZero() || len(tok.DER) == 0 {
					t.Fatalf("ParseResponse = %v, %v", tok, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseResponseBadSignature(t *testing.T) {
	a := tsatest.New(t)
	digest := timestamp.Digest(payload)
	nonce, _ := timestamp.NewNonce()
	req, _ := timestamp.BuildRequest(digest, nonce, nil)
	resp, _ := a.Respond(req, tsatest.Grant)
	// The signature is the last thing in the SignedData; flipping a byte near the end breaks it.
	resp[len(resp)-3] ^= 0xff
	if _, err := timestamp.ParseResponse(resp, digest, nonce); !errors.Is(err, timestamp.ErrInvalid) {
		t.Fatalf("a tampered token was accepted: %v", err)
	}
}

func TestVerify(t *testing.T) {
	a := tsatest.New(t)
	digest := timestamp.Digest(payload)
	nonce, _ := timestamp.NewNonce()
	req, _ := timestamp.BuildRequest(digest, nonce, nil)
	resp, _ := a.Respond(req, tsatest.Grant)
	tok, err := timestamp.ParseResponse(resp, digest, nonce)
	if err != nil {
		t.Fatal(err)
	}

	if got, err := timestamp.Verify(tok.DER, payload, a.Roots); err != nil || !got.GenTime.Equal(tok.GenTime) {
		t.Fatalf("Verify = %v, %v", got, err)
	}
	if _, err := timestamp.Verify(tok.DER, []byte("test-fixture-changed"), a.Roots); !errors.Is(err, timestamp.ErrImprint) {
		t.Fatalf("a changed payload: %v", err)
	}
	// An unrelated CA is not trusted.
	b := tsatest.New(t)
	if _, err := timestamp.Verify(tok.DER, payload, b.Roots); !errors.Is(err, timestamp.ErrUntrusted) {
		t.Fatalf("an untrusted chain: %v", err)
	}
	if _, err := timestamp.Verify(tok.DER, payload, x509.NewCertPool()); !errors.Is(err, timestamp.ErrUntrusted) {
		t.Fatalf("an empty trust store: %v", err)
	}
	if _, err := timestamp.Verify(tok.DER, payload, nil); err == nil {
		t.Fatal("nil roots were accepted")
	}
	if _, err := timestamp.Verify([]byte("test-fixture"), payload, a.Roots); !errors.Is(err, timestamp.ErrInvalid) {
		t.Fatalf("garbage: %v", err)
	}

	// A token stamped after the certificate expired is refused.
	a.SetNow(func() time.Time { return time.Now().Add(72 * time.Hour) })
	late, _ := a.Respond(req, tsatest.Grant)
	if lt, err := timestamp.ParseResponse(late, digest, nonce); err == nil {
		if _, err := timestamp.Verify(lt.DER, payload, a.Roots); err == nil {
			t.Fatal("a token stamped outside the certificate validity was accepted")
		}
	}
}
