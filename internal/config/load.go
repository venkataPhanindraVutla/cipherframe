package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Defaults.
const (
	defaultAPIListen  = ":8080"
	defaultEdgeListen = ":8081"
	defaultS3Region   = "us-east-1"
)

// FromOS loads the configuration from the process environment and files.
func FromOS() (*Config, error) { return Load(os.LookupEnv, os.ReadFile) }

// Load builds a Config from lookupEnv and readFile. It collects every problem
// and returns them joined; messages name variables, never values.
func Load(lookupEnv func(string) (string, bool), readFile func(string) ([]byte, error)) (*Config, error) {
	l := &loader{look: lookupEnv, read: readFile}
	c := l.load()
	if err := errors.Join(l.errs...); err != nil {
		return nil, err
	}
	return c, nil
}

type loader struct {
	look func(string) (string, bool)
	read func(string) ([]byte, error)
	errs []error
}

func (l *loader) errf(format string, a ...any) { l.errs = append(l.errs, fmt.Errorf(format, a...)) }

// plain returns a non-secret variable; absent or empty gives def.
func (l *loader) plain(name, def string) string {
	if v, ok := l.look(name); ok && v != "" {
		return v
	}
	return def
}

// secret reads a secret variable X or X_FILE. present is false when neither is
// set. Setting both, or an unreadable file, is an error and reports not present.
func (l *loader) secret(name string) (value string, present bool) {
	direct, hasDirect := l.look(name)
	path, hasFile := l.look(name + "_FILE")
	switch {
	case hasDirect && hasFile:
		l.errf("%s and %s_FILE are both set; set only one", name, name)
		return "", false
	case hasFile:
		if path == "" {
			l.errf("%s_FILE is set but empty", name)
			return "", false
		}
		b, err := l.read(path)
		if err != nil {
			l.errf("%s_FILE: cannot read the file", name)
			return "", false
		}
		v := string(b)
		if strings.HasSuffix(v, "\r\n") {
			v = v[:len(v)-2]
		} else if strings.HasSuffix(v, "\n") {
			v = v[:len(v)-1]
		}
		return v, true
	case hasDirect:
		return direct, true
	}
	return "", false
}

func isPlaceholder(s string) bool { return strings.HasPrefix(s, PlaceholderPrefix) }

func (l *loader) load() *Config {
	c := &Config{}

	// Environment. An invalid value is an error and is treated as production
	// for the secret checks below, so the loader fails closed.
	prod := true
	switch Environment(l.plain(EnvEnv, string(Development))) {
	case Development:
		c.Env, prod = Development, false
	case Production:
		c.Env = Production
	default:
		l.errf("%s must be %q or %q", EnvEnv, Development, Production)
	}

	c.LogLevel = l.logLevel()
	c.APIListen = l.listen(EnvAPIListen, defaultAPIListen)
	c.EdgeListen = l.listen(EnvEdgeListen, defaultEdgeListen)
	c.DatabaseURL = l.databaseURL(prod)
	c.S3 = l.s3(prod)
	c.Uploads = l.uploads()
	c.Peppers = l.peppers(prod)
	c.KMS = l.kms(prod)
	c.Media = l.media()
	return c
}

func (l *loader) logLevel() slog.Level {
	switch strings.ToLower(l.plain(EnvLogLevel, "info")) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	l.errf("%s must be one of debug, info, warn, error", EnvLogLevel)
	return slog.LevelInfo
}

func (l *loader) listen(name, def string) string {
	v := l.plain(name, def)
	_, port, err := net.SplitHostPort(v)
	if err != nil {
		l.errf("%s must be host:port", name)
		return v
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n < 1 {
		l.errf("%s port must be a number from 1 to 65535", name)
	}
	return v
}

func (l *loader) databaseURL(prod bool) Secret {
	v, ok := l.secret(EnvDatabaseURL)
	if !ok || v == "" {
		l.errf("%s is required", EnvDatabaseURL)
		return Secret{}
	}
	u, err := url.Parse(v)
	switch {
	case err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "":
		l.errf("%s must be a postgres:// or postgresql:// URL", EnvDatabaseURL)
	case prod && u.User != nil:
		if pw, _ := u.User.Password(); isPlaceholder(pw) {
			l.errf("%s contains a development placeholder; not allowed in production", EnvDatabaseURL)
		}
	}
	if prod && isPlaceholder(v) {
		l.errf("%s is a development placeholder; not allowed in production", EnvDatabaseURL)
	}
	return NewSecret(v)
}

func (l *loader) endpoint(name string) string {
	v := l.plain(name, "")
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		l.errf("%s must be an absolute http or https URL", name)
	}
	return v
}

func validBucketName(s string) bool {
	if len(s) < 3 || len(s) > 63 || strings.Contains(s, "..") {
		return false
	}
	alnum := func(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') }
	if !alnum(s[0]) || !alnum(s[len(s)-1]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b := s[i]; !alnum(b) && b != '-' && b != '.' {
			return false
		}
	}
	return true
}

func (l *loader) bucket(name string) string {
	v := l.plain(name, "")
	switch {
	case v == "":
		l.errf("%s is required", name)
	case !validBucketName(v):
		l.errf("%s is not a valid S3 bucket name", name)
	}
	return v
}

func (l *loader) credential(name string, prod bool) Credential {
	v, ok := l.secret(name)
	switch {
	case !ok:
		if prod {
			l.errf("%s must be set in production (use an empty value for the provider credential chain)", name)
		}
		return Credential{}
	case v == "":
		return NewStaticCredential("")
	}
	if prod && isPlaceholder(v) {
		l.errf("%s is a development placeholder; not allowed in production", name)
	}
	return NewStaticCredential(v)
}

func (l *loader) s3(prod bool) S3 {
	s := S3{
		Endpoint:       l.endpoint(EnvS3Endpoint),
		PublicEndpoint: l.endpoint(EnvS3PublicEndpoint),
		Region:         l.plain(EnvS3Region, defaultS3Region),
	}
	if s.PublicEndpoint == "" {
		s.PublicEndpoint = s.Endpoint
	}
	if v := l.plain(EnvS3ForcePathStyle, ""); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			l.errf("%s must be a boolean", EnvS3ForcePathStyle)
		}
		s.ForcePathStyle = b
	}
	s.SourceBucket = l.bucket(EnvS3SourceBucket)
	s.DeliveryBucket = l.bucket(EnvS3DeliveryBucket)
	if s.SourceBucket != "" && s.SourceBucket == s.DeliveryBucket {
		l.errf("%s and %s must differ", EnvS3SourceBucket, EnvS3DeliveryBucket)
	}
	s.AccessKeyID = l.credential(EnvS3AccessKeyID, prod)
	s.SecretAccessKey = l.credential(EnvS3SecretAccessKey, prod)
	if s.AccessKeyID.State() != s.SecretAccessKey.State() {
		l.errf("%s and %s must be in the same state (both unset, both empty, or both set)",
			EnvS3AccessKeyID, EnvS3SecretAccessKey)
	}
	return s
}

func (l *loader) peppers(prod bool) Peppers {
	var p Peppers
	raw, ok := l.secret(EnvAPIKeyPeppers)
	switch {
	case !ok || raw == "":
		l.errf("%s is required", EnvAPIKeyPeppers)
	default:
		m, errs := parsePeppers(raw)
		l.errs = append(l.errs, errs...)
		p.byVersion = m
		if prod {
			// A pepper is a placeholder if its decoded bytes start with the prefix.
			for _, v := range p.Versions() {
				if isPlaceholder(m[v].Reveal()) {
					l.errf("%s: version %d is a development placeholder; not allowed in production", EnvAPIKeyPeppers, v)
				}
			}
		}
	}

	cur := l.plain(EnvAPIKeyPepperCurrent, "")
	n, valid := parseVersion(cur)
	switch {
	case cur == "":
		l.errf("%s is required", EnvAPIKeyPepperCurrent)
	case !valid:
		l.errf("%s must be a positive integer", EnvAPIKeyPepperCurrent)
	case len(p.byVersion) > 0:
		if _, found := p.byVersion[n]; !found {
			l.errf("%s names version %d, which is not in %s", EnvAPIKeyPepperCurrent, n, EnvAPIKeyPeppers)
		}
	}
	if valid {
		p.current = n
	}
	return p
}
