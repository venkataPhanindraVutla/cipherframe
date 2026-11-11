package local_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
)

func keys() map[int][]byte {
	return map[int][]byte{
		1: bytes.Repeat([]byte{0x11}, config.KEKBytes),
		2: bytes.Repeat([]byte{0x22}, config.KEKBytes),
	}
}

func build(t *testing.T, current int) *local.Provider {
	t.Helper()
	p, err := local.NewFromKeys(config.Development, keys(), current, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConformance(t *testing.T) {
	kmstest.Run(t,
		func(t *testing.T) kms.Provider { return build(t, 1) },
		kmstest.WithRotated(func(t *testing.T) kms.Provider { return build(t, 2) }),
	)
}

func TestRefusesNonDevelopment(t *testing.T) {
	for _, env := range []config.Environment{config.Production, "", "staging"} {
		p, err := local.NewFromKeys(env, keys(), 1, nil)
		if !errors.Is(err, local.ErrProduction) || p != nil {
			t.Fatalf("env %q: want ErrProduction, got %v", env, err)
		}
	}
}

func TestRejectsBadKeySets(t *testing.T) {
	tests := map[string]struct {
		keys    map[int][]byte
		current int
	}{
		"empty":           {map[int][]byte{}, 1},
		"short key":       {map[int][]byte{1: make([]byte, 31)}, 1},
		"long key":        {map[int][]byte{1: make([]byte, 33)}, 1},
		"current missing": {keys(), 3},
		"zero version":    {map[int][]byte{0: make([]byte, 32)}, 0},
	}
	for name, tc := range tests {
		if _, err := local.NewFromKeys(config.Development, tc.keys, tc.current, nil); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestWarnsAtStartup(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	if _, err := local.NewFromKeys(config.Development, keys(), 1, log); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"level":"WARN"`) || !strings.Contains(out, "DEVELOPMENT-ONLY") {
		t.Fatalf("missing development-only warning: %s", out)
	}
	assertNoKeys(t, out)
}

func TestUnwrapUnknownVersionIsNotConfigured(t *testing.T) {
	ctx := context.Background()
	two := build(t, 2)
	w, err := two.Wrap(ctx, []byte("0123456789abcdef"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	onlyOne, err := local.NewFromKeys(config.Development, map[int][]byte{1: keys()[1]}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := onlyOne.Unwrap(ctx, w, []byte("aad"))
	if got != nil || !errors.Is(err, kms.ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured and no key, got %v", err)
	}
	if errors.Is(err, kms.ErrInvalid) {
		t.Fatal("a removed KEK must not be reported as tampering")
	}
}

func TestMetadataChangesFailClosed(t *testing.T) {
	ctx := context.Background()
	p := build(t, 2)
	w, err := p.Wrap(ctx, []byte("0123456789abcdef"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	// Pointing the ciphertext at another KEK version must not unwrap.
	other := w
	other.Version = "1"
	if got, err := p.Unwrap(ctx, other, []byte("aad")); err == nil || got != nil {
		t.Fatal("ciphertext opened under the wrong KEK version")
	}
	// The format byte is authenticated as well as checked.
	other = w
	other.Ciphertext = append([]byte{2}, w.Ciphertext[1:]...)
	if got, err := p.Unwrap(ctx, other, []byte("aad")); !errors.Is(err, kms.ErrInvalid) || got != nil {
		t.Fatal("unknown format version accepted")
	}
}

func TestCiphertextLayout(t *testing.T) {
	w, err := build(t, 1).Wrap(context.Background(), []byte("0123456789abcdef"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if w.Ciphertext[0] != 1 || len(w.Ciphertext) != 1+12+16+16 {
		t.Fatalf("layout: first byte %d, length %d", w.Ciphertext[0], len(w.Ciphertext))
	}
	if w.Provider != "local" || w.KeyID != "local" || w.Version != "1" {
		t.Fatal("wrapped key does not record provider, key id and version")
	}
}

func assertNoKeys(t *testing.T, out string) {
	t.Helper()
	for v, k := range keys() {
		for _, enc := range []string{
			string(k), hex.EncodeToString(k), strings.ToUpper(hex.EncodeToString(k)),
			base64.StdEncoding.EncodeToString(k), base64.RawStdEncoding.EncodeToString(k),
		} {
			if strings.Contains(out, enc) {
				t.Fatalf("KEK version %d appears in output", v)
			}
		}
	}
}

func TestProviderIsRedacted(t *testing.T) {
	p := build(t, 1)
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		outs = append(outs, fmt.Sprintf(verb, p), fmt.Sprintf(verb, *p))
	}
	j, _ := json.Marshal(p)
	outs = append(outs, string(j))
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("p", "provider", p)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("p", "provider", p)
	outs = append(outs, buf.String())
	for _, o := range outs {
		assertNoKeys(t, o)
	}
}

func TestErrorsNeverContainValues(t *testing.T) {
	ctx := context.Background()
	p := build(t, 1)
	pt := []byte("SECRET-plaintext-0123456789")
	aad := []byte("AAD-value-distinct")
	w, err := p.Wrap(ctx, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	w.Ciphertext[len(w.Ciphertext)-1] ^= 1
	_, err = p.Unwrap(ctx, w, aad)
	if err == nil {
		t.Fatal("expected failure")
	}
	for _, o := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		for _, s := range []string{
			string(pt), hex.EncodeToString(pt), string(aad), hex.EncodeToString(aad),
			hex.EncodeToString(w.Ciphertext), base64.StdEncoding.EncodeToString(w.Ciphertext),
		} {
			if strings.Contains(o, s) {
				t.Fatal("error output contains a value")
			}
		}
		assertNoKeys(t, o)
	}
}

func TestNewFromConfig(t *testing.T) {
	env := map[string]string{ //nolint:gosec // test fixture
		config.EnvDatabaseURL:         "postgres://app:pw@db:5432/cf",
		config.EnvS3SourceBucket:      "cf-source",
		config.EnvS3DeliveryBucket:    "cf-delivery",
		config.EnvAPIKeyPeppers:       "1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'p'}, 32)),
		config.EnvAPIKeyPepperCurrent: "1",
		config.EnvKMSLocalKEKs: "1:" + base64.StdEncoding.EncodeToString(keys()[1]) +
			",2:" + base64.StdEncoding.EncodeToString(keys()[2]),
		config.EnvKMSLocalKEKCurrent: "2",
	}
	cfg, err := config.Load(
		func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		func(string) ([]byte, error) { return nil, errors.New("no files") },
	)
	if err != nil {
		t.Fatal(err)
	}
	p, err := local.New(cfg.Env, cfg.KMS.LocalKEKs, nil)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := p.Current(context.Background())
	if err != nil || ref.Version != "2" || ref.KeyID != "local" {
		t.Fatalf("current = %+v, %v", ref, err)
	}
	if _, err := local.New(config.Production, cfg.KMS.LocalKEKs, nil); !errors.Is(err, local.ErrProduction) {
		t.Fatal("production must be refused")
	}
}
