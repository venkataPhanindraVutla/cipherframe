package config

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Upload variables (ADR 0025, 0026).
const (
	EnvEdgePublicURL   = "CIPHERFRAME_EDGE_PUBLIC_URL"
	EnvMaxSourceBytes  = "CIPHERFRAME_MAX_SOURCE_BYTES"
	EnvUploadTokenTTL  = "CIPHERFRAME_UPLOAD_TOKEN_TTL" //nolint:gosec // environment variable name, not a credential
	EnvUploadPartBytes = "CIPHERFRAME_UPLOAD_PART_BYTES"
)

// Upload defaults and bounds.
const (
	// DefaultMaxSourceBytes is the largest source upload: 10 GiB (ADR 0025).
	DefaultMaxSourceBytes int64 = 10 << 30
	// MaxSourceBytesCeiling is the largest value CIPHERFRAME_MAX_SOURCE_BYTES may take (the S3
	// object limit is 5 TiB).
	MaxSourceBytesCeiling int64 = 5 << 40
	// DefaultUploadTokenTTL is how long an upload token works.
	DefaultUploadTokenTTL = 24 * time.Hour
	// MinUploadTokenTTL and MaxUploadTokenTTL bound CIPHERFRAME_UPLOAD_TOKEN_TTL.
	MinUploadTokenTTL = time.Minute
	MaxUploadTokenTTL = 7 * 24 * time.Hour
	// DefaultUploadPartBytes is the part size of multipart uploads: 64 MiB.
	DefaultUploadPartBytes int64 = 64 << 20
	// MinUploadPartBytes is the S3 minimum for every part but the last.
	MinUploadPartBytes int64 = 5 << 20
	// MaxUploadPartBytes is the S3 maximum for one part.
	MaxUploadPartBytes int64 = 5 << 30
	// MaxUploadParts is the S3 limit on parts in one upload.
	MaxUploadParts int64 = 10000
)

// Uploads configures asset uploads.
type Uploads struct {
	// EdgePublicURL is the base URL browsers use to reach the edge listener, without a trailing
	// slash. The api role needs it to tell clients where to upload; it is empty when unset (the
	// server refuses to run the api role then).
	EdgePublicURL string
	// MaxSourceBytes is the largest source an asset may declare.
	MaxSourceBytes int64
	// TokenTTL is how long an upload token works.
	TokenTTL time.Duration
	// PartBytes is the part size clients are told to use for multipart uploads.
	PartBytes int64
}

func (l *loader) uploads() Uploads {
	u := Uploads{
		EdgePublicURL:  l.edgePublicURL(),
		MaxSourceBytes: l.byteSize(EnvMaxSourceBytes, DefaultMaxSourceBytes, 1<<20, MaxSourceBytesCeiling),
		TokenTTL:       l.duration(EnvUploadTokenTTL, DefaultUploadTokenTTL, MinUploadTokenTTL, MaxUploadTokenTTL),
		PartBytes:      l.byteSize(EnvUploadPartBytes, DefaultUploadPartBytes, MinUploadPartBytes, MaxUploadPartBytes),
	}
	if u.PartBytes > 0 && u.MaxSourceBytes > 0 && (u.MaxSourceBytes+u.PartBytes-1)/u.PartBytes > MaxUploadParts {
		l.errf("%s is too small for %s: a multipart upload may have at most %d parts",
			EnvUploadPartBytes, EnvMaxSourceBytes, MaxUploadParts)
	}
	return u
}

func (l *loader) edgePublicURL() string {
	v := l.plain(EnvEdgePublicURL, "")
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil || (u.Path != "" && u.Path != "/") {
		l.errf("%s must be an absolute http or https URL with no path, query or credentials", EnvEdgePublicURL)
		return ""
	}
	return strings.TrimSuffix(v, "/")
}

// byteSize reads a byte count (a plain integer) within [lo, hi].
func (l *loader) byteSize(name string, def, lo, hi int64) int64 {
	v := l.plain(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < lo || n > hi {
		l.errf("%s must be a whole number of bytes from %d to %d", name, lo, hi)
		return def
	}
	return n
}

func (l *loader) duration(name string, def, lo, hi time.Duration) time.Duration {
	v := l.plain(name, "")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < lo || d > hi {
		l.errf("%s must be a duration such as 24h, from %s to %s", name, lo, hi)
		return def
	}
	return d
}
