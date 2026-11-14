// Package timestamp builds RFC 3161 requests for a manifest payload and checks the tokens that come
// back (ADR 0041, M5-5). It stamps SHA-256 of the DSSE payload bytes, so how the envelope is stored
// never changes the imprint. The CMS and ASN.1 work is done by the digitorus/timestamp library.
//
// It imports no server, database or storage code, so the offline verifier can use it.
package timestamp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/digitorus/pkcs7"
	dt "github.com/digitorus/timestamp"
)

// Errors a check can return, wrapped with detail. Use errors.Is.
var (
	// ErrInvalid: the response is not a granted, well-formed token with a valid signature.
	ErrInvalid = errors.New("timestamp: invalid token")
	// ErrImprint: the token stamps something other than the expected digest.
	ErrImprint = errors.New("timestamp: the token does not stamp this manifest")
	// ErrNonce: the response does not echo the request's nonce.
	ErrNonce = errors.New("timestamp: the nonce does not match the request")
	// ErrUntrusted: the signer's certificate does not chain to a trusted root as a time-stamping
	// certificate at the stamped time.
	ErrUntrusted = errors.New("timestamp: the signing certificate is not trusted")
)

// nonceBits is the size of a request nonce.
const nonceBits = 64

// Token is a verified timestamp token.
type Token struct {
	DER     []byte // the DER TimeStampToken (a CMS SignedData)
	GenTime time.Time
}

// Digest is SHA-256 of a manifest payload: the value that is stamped.
func Digest(payload []byte) [sha256.Size]byte { return sha256.Sum256(payload) }

// NewNonce returns a random positive nonce.
func NewNonce() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), nonceBits))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

// BuildRequest returns the DER TimeStampReq for digest, with the nonce and certReq=true. policy may
// be nil.
func BuildRequest(digest [sha256.Size]byte, nonce *big.Int, policy asn1.ObjectIdentifier) ([]byte, error) {
	if nonce == nil || nonce.Sign() <= 0 {
		return nil, errors.New("timestamp: a positive nonce is required")
	}
	req := dt.Request{HashAlgorithm: crypto.SHA256, HashedMessage: digest[:], Certificates: true, Nonce: nonce}
	if len(policy) > 0 {
		req.TSAPolicyOID = policy
	}
	return req.Marshal()
}

// ParseResponse checks a DER TimeStampResp against the request that was sent: the status must be
// granted, the token signature must verify with the certificate it carries, and the imprint and
// nonce must match. It does not decide whether the signer is trusted; see [Verify].
func ParseResponse(resp []byte, digest [sha256.Size]byte, nonce *big.Int) (*Token, error) {
	ts, err := dt.ParseResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := checkToken(ts, digest); err != nil {
		return nil, err
	}
	if nonce == nil || ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
		return nil, ErrNonce
	}
	return &Token{DER: ts.RawToken, GenTime: ts.Time.UTC()}, nil
}

// checkToken requires a SHA-256 imprint equal to digest and an embedded certificate (without one
// the library cannot check the signature, so a token without it is not accepted).
func checkToken(ts *dt.Timestamp, digest [sha256.Size]byte) error {
	if !ts.AddTSACertificate || len(ts.Certificates) == 0 {
		return fmt.Errorf("%w: the token carries no certificate", ErrInvalid)
	}
	if ts.HashAlgorithm != crypto.SHA256 || !bytes.Equal(ts.HashedMessage, digest[:]) {
		return ErrImprint
	}
	return nil
}

// Verify checks a DER token for payload: the token signature, an imprint equal to SHA-256 of
// payload, and a signer certificate that chains to roots with the time-stamping usage, checked at
// the token's own time. roots must not be nil (use x509.SystemCertPool for the system roots).
func Verify(token, payload []byte, roots *x509.CertPool) (*Token, error) {
	if roots == nil {
		return nil, errors.New("timestamp: trusted roots are required")
	}
	ts, err := dt.Parse(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := checkToken(ts, Digest(payload)); err != nil {
		return nil, err
	}
	p7, err := pkcs7.Parse(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	err = p7.VerifyWithOpts(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, CurrentTime: ts.Time,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUntrusted, err)
	}
	return &Token{DER: token, GenTime: ts.Time.UTC()}, nil
}
