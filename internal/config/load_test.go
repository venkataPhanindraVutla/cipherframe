package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"testing"
)

type env map[string]string

func (e env) with(kv ...string) env {
	out := env{}
	for k, v := range e {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "\x00" {
			delete(out, kv[i])
		} else {
			out[kv[i]] = kv[i+1]
		}
	}
	return out
}

func pepper(fill byte, n int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, n))
}

func placeholderPepper() string {
	return base64.StdEncoding.EncodeToString([]byte(PlaceholderPrefix + strings.Repeat("x", 20)))
}

// base is a valid development environment.
var base = env{ //nolint:gosec // test fixture
	EnvDatabaseURL:         "postgres://app:pw@db:5432/cipherframe",
	EnvS3SourceBucket:      "cf-source",
	EnvS3DeliveryBucket:    "cf-delivery",
	EnvAPIKeyPeppers:       "1:" + pepper('a', 32),
	EnvAPIKeyPepperCurrent: "1",
	EnvKMSLocalKEKs:        "1:" + pepper('k', KEKBytes),
	EnvKMSLocalKEKCurrent:  "1",
}

// prod is a valid production environment.
var prod = base.with(
	EnvEnv, "production",
	EnvKMSProvider, ProviderVault,
	EnvS3AccessKeyID, "",
	EnvS3SecretAccessKey, "",
)

func load(e env, files map[string]string) (*Config, error) {
	return Load(
		func(k string) (string, bool) { v, ok := e[k]; return v, ok },
		func(p string) ([]byte, error) {
			if v, ok := files[p]; ok {
				return []byte(v), nil
			}
			return nil, fs.ErrNotExist
		},
	)
}

func TestDefaults(t *testing.T) {
	c, err := load(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Env != Development || c.LogLevel != slog.LevelInfo || c.APIListen != ":8080" || c.EdgeListen != ":8081" {
		t.Fatalf("unexpected defaults: %v %v %v %v", c.Env, c.LogLevel, c.APIListen, c.EdgeListen)
	}
	if c.S3.Region != "us-east-1" || c.S3.ForcePathStyle || c.S3.Endpoint != "" || c.S3.PublicEndpoint != "" {
		t.Fatalf("unexpected S3 defaults: %+v", c.S3)
	}
	if c.S3.AccessKeyID.State() != Unset || c.S3.SecretAccessKey.State() != Unset {
		t.Fatal("credentials must default to unset")
	}
	if cur, s := c.Peppers.Current(); cur != 1 || len(s.Reveal()) != 32 {
		t.Fatal("pepper not loaded")
	}
	if c.DatabaseURL.Reveal() != base[EnvDatabaseURL] {
		t.Fatal("database url not loaded")
	}
}

func TestPublicEndpointDefaultsToEndpoint(t *testing.T) {
	c, err := load(base.with(EnvS3Endpoint, "http://minio:9000"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.S3.PublicEndpoint != "http://minio:9000" {
		t.Fatalf("got %q", c.S3.PublicEndpoint)
	}
	c, err = load(base.with(EnvS3Endpoint, "http://minio:9000", EnvS3PublicEndpoint, "https://cdn.example.com"), nil)
	if err != nil || c.S3.PublicEndpoint != "https://cdn.example.com" {
		t.Fatalf("explicit public endpoint lost: %v", err)
	}
}

func TestValues(t *testing.T) {
	c, err := load(base.with(
		EnvLogLevel, "DEBUG", EnvAPIListen, "127.0.0.1:9000", EnvEdgeListen, "[::1]:9001",
		EnvS3ForcePathStyle, "true", EnvS3Region, "eu-west-1",
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.LogLevel != slog.LevelDebug || c.APIListen != "127.0.0.1:9000" || !c.S3.ForcePathStyle || c.S3.Region != "eu-west-1" {
		t.Fatalf("unexpected: %+v", c)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		env  env
		want string // substring naming the variable
	}{
		{"bad env", base.with(EnvEnv, "staging"), EnvEnv},
		{"bad log level", base.with(EnvLogLevel, "loud"), EnvLogLevel},
		{"listen no port", base.with(EnvAPIListen, "localhost"), EnvAPIListen},
		{"listen port zero", base.with(EnvAPIListen, ":0"), EnvAPIListen},
		{"listen port too big", base.with(EnvEdgeListen, ":65536"), EnvEdgeListen},
		{"listen named port", base.with(EnvEdgeListen, ":http"), EnvEdgeListen},
		{"db missing", base.with(EnvDatabaseURL, "\x00"), EnvDatabaseURL},
		{"db empty", base.with(EnvDatabaseURL, ""), EnvDatabaseURL},
		{"db wrong scheme", base.with(EnvDatabaseURL, "mysql://u:p@h/d"), EnvDatabaseURL},
		{"db not a url", base.with(EnvDatabaseURL, "not a url"), EnvDatabaseURL},
		{"db no host", base.with(EnvDatabaseURL, "postgres:///db"), EnvDatabaseURL},
		{"endpoint relative", base.with(EnvS3Endpoint, "minio:9000"), EnvS3Endpoint},
		{"endpoint ftp", base.with(EnvS3Endpoint, "ftp://minio"), EnvS3Endpoint},
		{"public endpoint bad", base.with(EnvS3PublicEndpoint, "/x"), EnvS3PublicEndpoint},
		{"bad bool", base.with(EnvS3ForcePathStyle, "maybe"), EnvS3ForcePathStyle},
		{"source missing", base.with(EnvS3SourceBucket, "\x00"), EnvS3SourceBucket},
		{"delivery missing", base.with(EnvS3DeliveryBucket, "\x00"), EnvS3DeliveryBucket},
		{"bucket too short", base.with(EnvS3SourceBucket, "ab"), EnvS3SourceBucket},
		{"bucket too long", base.with(EnvS3SourceBucket, strings.Repeat("a", 64)), EnvS3SourceBucket},
		{"bucket uppercase", base.with(EnvS3DeliveryBucket, "Bucket"), EnvS3DeliveryBucket},
		{"bucket underscore", base.with(EnvS3DeliveryBucket, "my_bucket"), EnvS3DeliveryBucket},
		{"bucket leading hyphen", base.with(EnvS3SourceBucket, "-abc"), EnvS3SourceBucket},
		{"bucket trailing dot", base.with(EnvS3SourceBucket, "abc."), EnvS3SourceBucket},
		{"buckets equal", base.with(EnvS3SourceBucket, "same-one", EnvS3DeliveryBucket, "same-one"), "must differ"},
		{"peppers missing", base.with(EnvAPIKeyPeppers, "\x00"), EnvAPIKeyPeppers},
		{"pepper no colon", base.with(EnvAPIKeyPeppers, pepper('a', 32)), EnvAPIKeyPeppers},
		{"pepper bad version", base.with(EnvAPIKeyPeppers, "x:"+pepper('a', 32)), "invalid version"},
		{"pepper zero version", base.with(EnvAPIKeyPeppers, "0:"+pepper('a', 32)), "invalid version"},
		{"pepper negative version", base.with(EnvAPIKeyPeppers, "-1:"+pepper('a', 32)), "invalid version"},
		{"pepper bad base64", base.with(EnvAPIKeyPeppers, "1:!!!"), "base64"},
		{"pepper short", base.with(EnvAPIKeyPeppers, "1:"+pepper('a', 31)), "shorter than 32"},
		{"pepper duplicate", base.with(EnvAPIKeyPeppers, "1:"+pepper('a', 32)+",1:"+pepper('b', 32)), "more than once"},
		{"pepper empty entry", base.with(EnvAPIKeyPeppers, "1:"+pepper('a', 32)+","), EnvAPIKeyPeppers},
		{"current missing", base.with(EnvAPIKeyPepperCurrent, "\x00"), EnvAPIKeyPepperCurrent},
		{"current not a number", base.with(EnvAPIKeyPepperCurrent, "one"), EnvAPIKeyPepperCurrent},
		{"current not in set", base.with(EnvAPIKeyPepperCurrent, "2"), "not in"},
		{"credential mismatch", base.with(EnvS3AccessKeyID, "AKIAvalue"), "same state"},
		{"credential mismatch chain", base.with(EnvS3AccessKeyID, "", EnvS3SecretAccessKey, "x"), "same state"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(tc.env, nil)
			if err == nil || c != nil {
				t.Fatalf("expected an error, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestAllProblemsCollected(t *testing.T) {
	_, err := load(env{EnvLogLevel: "loud", EnvAPIListen: "x"}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, v := range []string{EnvLogLevel, EnvAPIListen, EnvDatabaseURL, EnvS3SourceBucket, EnvAPIKeyPeppers, EnvAPIKeyPepperCurrent} {
		if !strings.Contains(err.Error(), v) {
			t.Errorf("missing %s in %q", v, err)
		}
	}
}

func TestFileVariables(t *testing.T) {
	pep := "1:" + pepper('z', 40)
	tests := []struct {
		name    string
		content string
	}{
		{"no newline", pep},
		{"lf", pep + "\n"},
		{"crlf", pep + "\r\n"},
	}
	for _, tc := range tests {
		t.Run("trim "+tc.name, func(t *testing.T) {
			e := base.with(EnvAPIKeyPeppers, "\x00", EnvAPIKeyPeppers+"_FILE", "/run/secrets/peppers")
			c, err := load(e, map[string]string{"/run/secrets/peppers": tc.content})
			if err != nil {
				t.Fatal(err)
			}
			if _, s := c.Peppers.Current(); len(s.Reveal()) != 40 {
				t.Fatal("pepper from file not parsed")
			}
		})
	}

	t.Run("only one newline trimmed", func(t *testing.T) {
		e := base.with(EnvDatabaseURL, "\x00", EnvDatabaseURL+"_FILE", "/db")
		c, err := load(e, map[string]string{"/db": "postgres://u:p@h/d\n\n"}) //nolint:gosec // test fixture
		if err == nil && c != nil {
			t.Fatal("second newline must be kept, making the URL invalid")
		}
	})

	t.Run("both set", func(t *testing.T) {
		e := base.with(EnvDatabaseURL+"_FILE", "/db")
		_, err := load(e, map[string]string{"/db": "postgres://u:p@h/d"}) //nolint:gosec // test fixture
		if err == nil || !strings.Contains(err.Error(), "both set") || !strings.Contains(err.Error(), EnvDatabaseURL) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("unreadable", func(t *testing.T) {
		e := base.with(EnvDatabaseURL, "\x00", EnvDatabaseURL+"_FILE", "/secret/path")
		_, err := load(e, nil)
		if err == nil || !strings.Contains(err.Error(), EnvDatabaseURL+"_FILE") || strings.Contains(err.Error(), "/secret/path") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("empty path", func(t *testing.T) {
		e := base.with(EnvDatabaseURL, "\x00", EnvDatabaseURL+"_FILE", "")
		if _, err := load(e, nil); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("every secret variable supports _FILE", func(t *testing.T) {
		e := base.with(
			EnvDatabaseURL, "\x00", EnvDatabaseURL+"_FILE", "/a",
			EnvS3AccessKeyID+"_FILE", "/b", EnvS3SecretAccessKey+"_FILE", "/c",
			EnvAPIKeyPeppers, "\x00", EnvAPIKeyPeppers+"_FILE", "/d",
		)
		c, err := load(e, map[string]string{ //nolint:gosec // test fixture
			"/a": "postgres://u:p@h/d\n", "/b": "AKIA\n", "/c": "sek\r\n", "/d": pepperEntry(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if c.S3.AccessKeyID.Secret().Reveal() != "AKIA" || c.S3.SecretAccessKey.Secret().Reveal() != "sek" {
			t.Fatal("credential files not trimmed")
		}
	})

	t.Run("empty credential file is provider chain", func(t *testing.T) {
		e := base.with(EnvS3AccessKeyID+"_FILE", "/b", EnvS3SecretAccessKey, "")
		c, err := load(e, map[string]string{"/b": "\n"})
		if err != nil || c.S3.AccessKeyID.State() != ProviderChain {
			t.Fatalf("got %v", err)
		}
	})
}

func pepperEntry() string { return "1:" + pepper('q', 32) + "\n" }

func TestCredentialStatesLoaded(t *testing.T) {
	tests := []struct {
		name  string
		env   env
		state CredentialState
	}{
		{"unset", base, Unset},
		{"provider chain", base.with(EnvS3AccessKeyID, "", EnvS3SecretAccessKey, ""), ProviderChain},
		{"static", base.with(EnvS3AccessKeyID, "AKIAvalue", EnvS3SecretAccessKey, "sekvalue"), Static},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(tc.env, nil)
			if err != nil {
				t.Fatal(err)
			}
			if c.S3.AccessKeyID.State() != tc.state || c.S3.SecretAccessKey.State() != tc.state {
				t.Fatalf("states %v %v, want %v", c.S3.AccessKeyID.State(), c.S3.SecretAccessKey.State(), tc.state)
			}
		})
	}
}

func TestPepperParsing(t *testing.T) {
	c, err := load(base.with(
		EnvAPIKeyPeppers, "2:"+pepper('b', 32)+" , 1:"+pepper('a', 48),
		EnvAPIKeyPepperCurrent, "2",
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(c.Peppers.Versions()); got != "[1 2]" {
		t.Fatalf("versions %s", got)
	}
	old, ok := c.Peppers.Get(1)
	if !ok || len(old.Reveal()) != 48 {
		t.Fatal("version 1 lost")
	}
	if _, ok := c.Peppers.Get(3); ok {
		t.Fatal("unexpected version 3")
	}
	if cur, s := c.Peppers.Current(); cur != 2 || s.Reveal() != strings.Repeat("b", 32) {
		t.Fatal("current wrong")
	}
}

func TestProduction(t *testing.T) {
	if _, err := load(prod, nil); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}

	tests := []struct {
		name string
		env  env
		want string
	}{
		{"placeholder db password", prod.with(EnvDatabaseURL, "postgres://app:dev-placeholder-x@db/cf"), EnvDatabaseURL},
		{"placeholder pepper", prod.with(EnvAPIKeyPeppers, "1:"+placeholderPepper()), EnvAPIKeyPeppers},
		{"placeholder access key", prod.with(EnvS3AccessKeyID, PlaceholderPrefix+"a", EnvS3SecretAccessKey, "real-secret"), EnvS3AccessKeyID},
		{"placeholder secret key", prod.with(EnvS3AccessKeyID, "AKIAreal", EnvS3SecretAccessKey, PlaceholderPrefix+"b"), EnvS3SecretAccessKey},
		{"missing db", prod.with(EnvDatabaseURL, "\x00"), EnvDatabaseURL},
		{"missing peppers", prod.with(EnvAPIKeyPeppers, "\x00"), EnvAPIKeyPeppers},
		{"unset credentials", prod.with(EnvS3AccessKeyID, "\x00", EnvS3SecretAccessKey, "\x00"), EnvS3AccessKeyID},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(tc.env, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want mention of %s", err, tc.want)
			}
		})
	}

	t.Run("static and provider chain accepted", func(t *testing.T) {
		if _, err := load(prod.with(EnvS3AccessKeyID, "AKIAreal", EnvS3SecretAccessKey, "real"), nil); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDevelopmentAcceptsPlaceholders(t *testing.T) {
	c, err := load(base.with(
		EnvDatabaseURL, "postgres://app:dev-placeholder-x@db/cf",
		EnvAPIKeyPeppers, "1:"+placeholderPepper(),
		EnvS3AccessKeyID, PlaceholderPrefix+"a", EnvS3SecretAccessKey, PlaceholderPrefix+"b",
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.S3.AccessKeyID.State() != Static {
		t.Fatal("placeholder credential should be static")
	}
}

// TestRedaction loads a configuration with distinctive secrets, prints and logs
// it every way we can, and asserts that no secret value appears.
func TestRedaction(t *testing.T) {
	const (
		dbPass  = "DBPASS-distinct-7f3a"
		akid    = "AKID-distinct-91bc"
		sak     = "SAK-distinct-c40d"
		pepRaw  = "PEPPER-distinct-bytes-0123456789ab"
		pepRaw2 = "PEPPER2-distinct-bytes-0123456789a"
	)
	pep1 := base64.StdEncoding.EncodeToString([]byte(pepRaw))
	pep2 := base64.StdEncoding.EncodeToString([]byte(pepRaw2))
	const (
		kekRaw1 = "KEK1-distinct-bytes-0123456789ab" // exactly KEKBytes
		kekRaw2 = "KEK2-distinct-bytes-0123456789ab"
	)
	kek1 := base64.StdEncoding.EncodeToString([]byte(kekRaw1))
	kek2 := base64.StdEncoding.EncodeToString([]byte(kekRaw2))
	e := base.with(
		EnvDatabaseURL, "postgres://app:"+dbPass+"@db:5432/cf",
		EnvS3AccessKeyID, akid, EnvS3SecretAccessKey, sak,
		EnvAPIKeyPeppers, "1:"+pep1+",2:"+pep2, EnvAPIKeyPepperCurrent, "2",
		EnvKMSLocalKEKs, "1:"+kek1+",2:"+kek2, EnvKMSLocalKEKCurrent, "2",
	)
	c, err := load(e, nil)
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{dbPass, akid, sak, pepRaw, pepRaw2, pep1, pep2, e[EnvDatabaseURL], kekRaw1, kekRaw2, kek1, kek2}

	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		outs = append(outs, fmt.Sprintf(verb, c), fmt.Sprintf(verb, *c), fmt.Sprintf(verb, c.S3),
			fmt.Sprintf(verb, c.Peppers), fmt.Sprintf(verb, c.KMS), fmt.Sprintf(verb, c.KMS.LocalKEKs), fmt.Sprintf(verb, c.DatabaseURL), fmt.Sprintf(verb, c.S3.AccessKeyID))
	}
	j, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	outs = append(outs, string(j))
	ji, _ := json.MarshalIndent(c, "", " ")
	outs = append(outs, string(ji))

	var jb, tb bytes.Buffer
	slog.New(slog.NewJSONHandler(&jb, &slog.HandlerOptions{Level: slog.LevelDebug})).Info("config", "config", c)
	slog.New(slog.NewJSONHandler(&jb, nil)).Info("config", slog.Any("cfg", c), slog.Any("peppers", c.Peppers))
	slog.New(slog.NewTextHandler(&tb, nil)).Info("config", "config", c)
	outs = append(outs, jb.String(), tb.String())

	for _, o := range outs {
		for _, s := range secrets {
			if strings.Contains(o, s) || strings.Contains(o, fmt.Sprintf("%x", s)) || strings.Contains(strings.ToUpper(o), fmt.Sprintf("%X", s)) {
				t.Fatal("a secret value appeared in printed or logged output")
			}
		}
	}
	if !strings.Contains(jb.String(), Redacted) || !strings.Contains(jb.String(), "static") {
		t.Fatalf("log output should show [redacted] and credential state: %s", jb.String())
	}
}

func TestErrorsNeverContainSecrets(t *testing.T) {
	const bad = "SECRET-distinct-zz91"
	tests := []env{
		base.with(EnvDatabaseURL, "mysql://u:"+bad+"@h/d"),
		base.with(EnvDatabaseURL, "postgres://u:"+bad+"@h:notaport/d"),
		base.with(EnvDatabaseURL, "%%"+bad),
		base.with(EnvAPIKeyPeppers, "1:"+bad),
		base.with(EnvAPIKeyPeppers, bad),
		base.with(EnvAPIKeyPeppers, bad+":"+pepper('a', 32)),
		base.with(EnvAPIKeyPeppers, "1:"+pepper('a', 32)+",1:"+bad),
		base.with(EnvS3AccessKeyID, bad),
		base.with(EnvS3AccessKeyID, bad, EnvS3SecretAccessKey, bad, EnvS3AccessKeyID+"_FILE", "/x"),
		prod.with(EnvDatabaseURL, "postgres://u:"+PlaceholderPrefix+bad+"@h/d"),
		prod.with(EnvS3AccessKeyID, PlaceholderPrefix+bad, EnvS3SecretAccessKey, PlaceholderPrefix+bad),
		base.with(EnvDatabaseURL, "\x00", EnvDatabaseURL+"_FILE", "/f"),
	}
	for i, e := range tests {
		_, err := load(e, map[string]string{"/f": bad})
		if err == nil {
			t.Fatalf("case %d: expected error", i)
		}
		if strings.Contains(err.Error(), bad) {
			t.Fatalf("case %d: error leaks a secret value: %v", i, errors.Unwrap(err))
		}
	}
}

func TestLogValueNil(t *testing.T) {
	var c *Config
	if c.LogValue().String() == "" {
		t.Fatal("nil config should log something harmless")
	}
}
