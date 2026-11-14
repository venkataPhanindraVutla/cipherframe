package offline

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/timestamp"
)

// MaxTimestampBytes is the largest timestamp document ParseTimestamp accepts.
const MaxTimestampBytes = 1 << 20

// TimestampDoc is the document `GET /v1/assets/{id}/manifest/timestamp` returns and
// `cipherframe verify --timestamp` reads (ADR 0041).
type TimestampDoc struct {
	Token         string    `json:"token"` // base64 DER TimeStampToken
	GenTime       time.Time `json:"gen_time"`
	TSAURL        string    `json:"tsa_url"`
	ImprintSHA256 string    `json:"imprint_sha256"`
}

// ParseTimestamp reads a timestamp document.
func ParseTimestamp(data []byte) (*TimestampDoc, error) {
	if len(data) > MaxTimestampBytes {
		return nil, errors.New("the timestamp document is too large")
	}
	var d TimestampDoc
	if err := json.Unmarshal(data, &d); err != nil || d.Token == "" {
		return nil, errors.New("the timestamp document is not valid JSON with a token")
	}
	return &d, nil
}

// RootsFromPEM builds a trust store from a PEM bundle (a --tsa-ca file).
func RootsFromPEM(pem []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("the CA bundle holds no PEM certificate")
	}
	return pool, nil
}

// VerifyTimestamp checks the token of doc against the manifest envelope: the imprint must be
// SHA-256 of the envelope's payload, the token signature must verify, and the signer must chain to
// roots as a time-stamping certificate. It returns the time the authority stamped, taken from the
// verified token (doc.GenTime is not trusted). It does not check the envelope's own signature;
// [Open] does that.
func VerifyTimestamp(envelope []byte, doc TimestampDoc, roots *x509.CertPool) (time.Time, error) {
	env, err := dsse.Decode(envelope)
	if err != nil {
		return time.Time{}, err
	}
	der, err := base64.StdEncoding.DecodeString(doc.Token)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: the token is not base64", timestamp.ErrInvalid)
	}
	tok, err := timestamp.Verify(der, env.Payload, roots)
	if err != nil {
		return time.Time{}, err
	}
	return tok.GenTime, nil
}

// TimestampReason is the short reason shown for a timestamp that does not verify.
func TimestampReason(err error) string {
	switch {
	case errors.Is(err, timestamp.ErrImprint):
		return "the token does not stamp this manifest"
	case errors.Is(err, timestamp.ErrUntrusted):
		return "the signing certificate is not trusted"
	case errors.Is(err, timestamp.ErrInvalid):
		return "the token is not valid"
	}
	return err.Error()
}
