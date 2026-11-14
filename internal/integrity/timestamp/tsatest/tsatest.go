// Package tsatest is an in-process RFC 3161 time-stamping authority for tests. It signs with a
// throwaway CA generated on the spot and never leaves the test process. Do not use it outside tests.
package tsatest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dt "github.com/digitorus/timestamp"
)

// Mode is how the authority answers.
type Mode int

// The modes.
const (
	Grant         Mode = iota // a valid token
	Reject                    // a rejection status
	WrongNonce                // a valid token for another nonce
	WrongImprint              // a valid token for another digest
	Garbage                   // not a TimeStampResp at all
	ServerError               // HTTP 503
	NoCertificate             // a granted token that carries no certificate
)

// TSA is a running test authority.
type TSA struct {
	URL     string // http://127.0.0.1:port, for CIPHERFRAME_ENV=development
	Roots   *x509.CertPool
	RootPEM []byte // the CA certificate, PEM, as a --tsa-ca file
	Policy  asn1.ObjectIdentifier

	srv   *httptest.Server
	ca    *x509.Certificate
	leaf  *x509.Certificate
	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	mode  Mode
	calls atomic.Int64
	now   func() time.Time
}

// New starts a TSA that is stopped when the test ends.
func New(t testing.TB) *TSA {
	t.Helper()
	caKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-fixture-tsa-root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	ca := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey))))
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test-fixture-tsa"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		// RFC 3161 wants the usage critical; the library has no setting for it, so the extension is
		// added by hand.
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: ekuTimeStamping}},
	}
	leaf := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey))))

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	a := &TSA{
		Roots: pool, RootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}),
		Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 1}, ca: ca, leaf: leaf, key: key, now: time.Now,
	}
	a.srv = httptest.NewServer(http.HandlerFunc(a.serve))
	a.URL = a.srv.URL
	t.Cleanup(a.srv.Close)
	return a
}

// ekuTimeStamping is the DER of ExtKeyUsageSyntax { id-kp-timeStamping }.
var ekuTimeStamping = []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08}

// SetMode changes how the authority answers from now on.
func (a *TSA) SetMode(m Mode) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mode = m
}

// SetNow sets the clock that stamps tokens.
func (a *TSA) SetNow(f func() time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.now = f
}

// Calls is the number of requests received.
func (a *TSA) Calls() int { return int(a.calls.Load()) }

// Respond answers a DER TimeStampReq the way the authority would in mode m (not over HTTP).
func (a *TSA) Respond(reqDER []byte, m Mode) ([]byte, error) {
	req, err := dt.ParseRequest(reqDER)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	now := a.now()
	a.mu.Unlock()
	switch m {
	case Reject:
		return dt.CreateErrorResponse(dt.Rejection, dt.BadAlgorithm)
	case Garbage:
		return []byte("test-fixture-not-asn1"), nil
	}
	tok := dt.Timestamp{
		HashAlgorithm: req.HashAlgorithm, HashedMessage: req.HashedMessage, Nonce: req.Nonce, Time: now.UTC(),
		Policy: a.Policy, AddTSACertificate: m != NoCertificate,
	}
	if len(req.TSAPolicyOID) > 0 {
		tok.Policy = req.TSAPolicyOID
	}
	switch m {
	case WrongNonce:
		tok.Nonce = new(big.Int).Add(req.Nonce, big.NewInt(1))
	case WrongImprint:
		tok.HashedMessage = append([]byte(nil), req.HashedMessage...)
		tok.HashedMessage[0] ^= 0xff
	}
	return tok.CreateResponseWithOpts(a.leaf, a.key, crypto.SHA256)
}

func (a *TSA) serve(w http.ResponseWriter, r *http.Request) {
	a.calls.Add(1)
	a.mu.Lock()
	m := a.mode
	a.mu.Unlock()
	if m == ServerError {
		http.Error(w, "test-fixture-unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil || r.Header.Get("Content-Type") != "application/timestamp-query" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resp, err := a.Respond(body, m)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	_, _ = w.Write(resp)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
