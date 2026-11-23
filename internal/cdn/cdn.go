// Package cdn signs CDN URLs for the delivery bucket and purges its cache (ADR 0062, 0065). Two
// providers are supported, CloudFront and Cloud CDN. Signing is plain standard-library crypto.
//
// A signed URL is a bearer credential until it expires. Nothing here logs, formats or returns one
// in an error, and errors never carry key material.
package cdn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
)

// Signer makes signed URLs for objects of the delivery bucket.
type Signer interface {
	// Sign returns a URL for the object key (no leading slash) that the CDN accepts until expires.
	// The expiry has whole-second precision, rounded down.
	Sign(key string, expires time.Time) (string, error)
}

// Purger removes cached copies of every object under an object key prefix.
type Purger interface {
	// Purge invalidates the objects whose key starts with prefix (for example "t/<tenant>/a/<asset>/").
	// It is idempotent: purging the same prefix twice is not an error.
	Purge(ctx context.Context, prefix string) error
}

// ErrBadKey is returned for an object key that is not made of the characters of Cipherframe's own
// object keys, so no URL needs escaping and the signed text is exactly the URL the player requests.
var ErrBadKey = errors.New("cdn: unexpected object key")

var keyRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// objectURL joins the base URL and key, rejecting keys that would need escaping or could climb out
// of the path.
func objectURL(base, key string) (string, error) {
	if !keyRE.MatchString(key) || strings.HasPrefix(key, "/") || strings.Contains(key, "..") {
		return "", ErrBadKey
	}
	return base + "/" + key, nil
}

// NewSigner builds the signer for cfg, reading the signing key from its file. It returns an error
// that names the setting, never the key or its content. cfg must be Enabled.
func NewSigner(cfg config.CDN) (Signer, error) {
	return newSigner(cfg, os.ReadFile)
}

func newSigner(cfg config.CDN, read func(string) ([]byte, error)) (Signer, error) {
	if cfg.SigningKeyFile == "" {
		return nil, fmt.Errorf("%s is required for the role that signs URLs", config.EnvCDNSigningKeyFile)
	}
	b, err := read(cfg.SigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read the file", config.EnvCDNSigningKeyFile)
	}
	var s Signer
	switch cfg.Provider {
	case config.CDNCloudFront:
		s, err = NewCloudFront(cfg.BaseURL, cfg.KeyID, b)
	case config.CDNCloudCDN:
		s, err = NewCloudCDN(cfg.BaseURL, cfg.KeyID, b)
	default:
		return nil, errors.New("cdn: no provider configured")
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", config.EnvCDNSigningKeyFile, err)
	}
	return s, nil
}

// epoch is the Unix time of t in whole seconds, rounded down.
func epoch(t time.Time) int64 { return t.Unix() }
