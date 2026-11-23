package cdn

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // Cloud CDN signed URLs are defined with HMAC-SHA1; there is no other option.
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// cloudCDNKeyBytes is the length of a Cloud CDN signing key: 16 random bytes.
const cloudCDNKeyBytes = 16

type cloudCDN struct {
	base    string
	keyName string
	key     []byte
}

// NewCloudCDN returns a signer for Cloud CDN signed URLs. base is the load balancer's URL
// (https://host), keyName the name of the signing key on the backend bucket, and key the key as
// Cloud CDN shows it: 16 bytes in URL-safe base64.
func NewCloudCDN(base, keyName string, key []byte) (Signer, error) {
	raw := strings.TrimSpace(string(key))
	b, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		if b, err = base64.RawURLEncoding.DecodeString(raw); err != nil {
			return nil, errors.New("the key must be 16 bytes in URL-safe base64")
		}
	}
	if len(b) != cloudCDNKeyBytes {
		return nil, errors.New("the key must be 16 bytes in URL-safe base64")
	}
	return &cloudCDN{base: strings.TrimSuffix(base, "/"), keyName: keyName, key: b}, nil
}

// Sign implements Signer: the URL, then Expires and KeyName, then the URL-safe base64 of the
// HMAC-SHA1 of everything before it.
func (c *cloudCDN) Sign(key string, expires time.Time) (string, error) {
	u, err := objectURL(c.base, key)
	if err != nil {
		return "", err
	}
	toSign := u + "?Expires=" + strconv.FormatInt(epoch(expires), 10) + "&KeyName=" + c.keyName
	mac := hmac.New(sha1.New, c.key) //nolint:gosec // see the import
	mac.Write([]byte(toSign))
	return toSign + "&Signature=" + base64.URLEncoding.EncodeToString(mac.Sum(nil)), nil
}
