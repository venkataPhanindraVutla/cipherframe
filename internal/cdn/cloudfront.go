package cdn

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // CloudFront signed URLs are defined with RSA-SHA1; there is no other option.
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"time"
)

type cloudFront struct {
	base  string
	keyID string
	key   *rsa.PrivateKey
}

// minRSABits is what CloudFront accepts: RSA 2048.
const minRSABits = 2048

// NewCloudFront returns a signer for CloudFront signed URLs with a canned policy. base is the
// distribution's URL (https://host), keyID the public key ID of a trusted key group, and keyPEM the
// RSA private key (PKCS#1 or PKCS#8 PEM).
func NewCloudFront(base, keyID string, keyPEM []byte) (Signer, error) {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, errors.New("the file is not a PEM private key")
	}
	var key *rsa.PrivateKey
	switch blk.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			return nil, errors.New("the PKCS#1 private key cannot be parsed")
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, errors.New("the PKCS#8 private key cannot be parsed")
		}
		var ok bool
		if key, ok = k.(*rsa.PrivateKey); !ok {
			return nil, errors.New("the key must be an RSA key")
		}
	default:
		return nil, errors.New("the PEM block must be an RSA private key")
	}
	if key.N.BitLen() < minRSABits {
		return nil, errors.New("the RSA key must be at least 2048 bits")
	}
	return &cloudFront{base: strings.TrimSuffix(base, "/"), keyID: keyID, key: key}, nil
}

// Sign implements Signer. The canned policy names the exact URL and the expiry; its RSA-SHA1
// signature is written in CloudFront's URL-safe base64 (+ becomes -, = becomes _, / becomes ~).
func (c *cloudFront) Sign(key string, expires time.Time) (string, error) {
	u, err := objectURL(c.base, key)
	if err != nil {
		return "", err
	}
	exp := strconv.FormatInt(epoch(expires), 10)
	policy := `{"Statement":[{"Resource":"` + u + `","Condition":{"DateLessThan":{"AWS:EpochTime":` + exp + `}}}]}`
	sum := sha1.Sum([]byte(policy)) //nolint:gosec // see the import
	sig, err := rsa.SignPKCS1v15(nil, c.key, crypto.SHA1, sum[:])
	if err != nil {
		return "", errors.New("cdn: signing failed")
	}
	enc := strings.NewReplacer("+", "-", "=", "_", "/", "~").Replace(base64.StdEncoding.EncodeToString(sig))
	return u + "?Expires=" + exp + "&Signature=" + enc + "&Key-Pair-Id=" + c.keyID, nil
}
