//go:build !nokms_gcp

package gcpkms_test

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/gcpkms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
)

func provider(t *testing.T, f *fakeKMS) (p *gcpkms.Provider, stop func()) {
	t.Helper()
	conn, stop := start(t, f)
	p, err := gcpkms.New(context.Background(),
		config.KMSGCP{KeyName: testKey, Timeout: 500 * time.Millisecond},
		option.WithGRPCConn(conn))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, stop
}

// clone returns a fake over the same key material whose primary is a newly added version.
func (f *fakeKMS) clone() *fakeKMS {
	f.mu.Lock()
	g := &fakeKMS{
		versions: map[uint32]cipher.AEAD{},
		state:    map[uint32]kmspb.CryptoKeyVersion_CryptoKeyVersionState{},
		primary:  f.primary,
		purpose:  f.purpose,
		failWith: map[string]codes.Code{},
		calls:    map[string]int{},
	}
	for k, v := range f.versions {
		g.versions[k] = v
		g.state[k] = f.state[k]
	}
	f.mu.Unlock()
	g.addVersion()
	return g
}

func TestConformance(t *testing.T) {
	var last *fakeKMS
	var lastStop func()
	kmstest.Run(t,
		func(t *testing.T) kms.Provider {
			last = newFake()
			p, stop := provider(t, last)
			lastStop = stop
			return p
		},
		kmstest.WithRotated(func(t *testing.T) kms.Provider {
			p, _ := provider(t, last.clone())
			return p
		}),
		kmstest.WithOutage(func(t *testing.T, _ kms.Provider) func() {
			lastStop() // closes the listener: every call now fails to connect
			return func() {}
		}),
	)
}

func TestRealGCPKMS(t *testing.T) {
	name := os.Getenv("CIPHERFRAME_TEST_GCP_KMS_KEY_NAME")
	if name == "" {
		t.Skip("CIPHERFRAME_TEST_GCP_KMS_KEY_NAME is not set; skipping the real Cloud KMS run")
	}
	cfg := config.KMSGCP{KeyName: name, Timeout: 10 * time.Second}
	kmstest.Run(t, func(t *testing.T) kms.Provider {
		p, err := gcpkms.New(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	})
}

func TestCurrentAndVersions(t *testing.T) {
	f := newFake()
	f.addVersion()
	f.addVersion() // primary is now version 3
	p, _ := provider(t, f)
	ref, err := p.Current(context.Background())
	if err != nil || ref.KeyID != testKey || ref.Version != "3" {
		t.Fatalf("current = %+v, %v", ref, err)
	}
	if p.Name() != "gcpkms" {
		t.Fatal("name")
	}
}

func TestCurrentRefusesUnusableKeys(t *testing.T) {
	tests := map[string]func(*fakeKMS){
		"asymmetric purpose": func(f *fakeKMS) { f.purpose = kmspb.CryptoKey_ASYMMETRIC_SIGN },
		"mac purpose":        func(f *fakeKMS) { f.purpose = kmspb.CryptoKey_MAC },
		"no primary":         func(f *fakeKMS) { f.primary = 0 },
		"primary disabled": func(f *fakeKMS) {
			f.state[f.primary] = kmspb.CryptoKeyVersion_DISABLED
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			f.set(mutate)
			p, _ := provider(t, f)
			if _, err := p.Current(context.Background()); !errors.Is(err, kms.ErrNotConfigured) {
				t.Fatalf("want ErrNotConfigured, got %v", err)
			}
		})
	}
}

func TestWrapSendsAADAndChecksums(t *testing.T) {
	f := newFake()
	p, _ := provider(t, f)
	aad := []byte("bind-me")
	if _, err := p.Wrap(context.Background(), []byte("0123456789abcdef"), aad); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !bytes.Equal(f.lastEncryptAAD, aad) {
		t.Fatal("associated data did not reach Cloud KMS")
	}
}

func TestOldVersionStaysReadableAfterRotation(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	p, _ := provider(t, f)
	w, err := p.Wrap(ctx, []byte("0123456789abcdef"), []byte("aad"))
	if err != nil || w.Version != "1" {
		t.Fatalf("wrap: %+v %v", w, err)
	}
	f.addVersion()
	if got, err := p.Unwrap(ctx, w, []byte("aad")); err != nil || string(got) != "0123456789abcdef" {
		t.Fatalf("old version no longer unwraps: %v", err)
	}
	w2, err := p.Wrap(ctx, []byte("0123456789abcdef"), []byte("aad"))
	if err != nil || w2.Version != "2" {
		t.Fatalf("new wrap should use version 2: %+v %v", w2, err)
	}
}

func TestDisabledVersionIsNotConfigured(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	p, _ := provider(t, f)
	w, err := p.Wrap(ctx, []byte("0123456789abcdef"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	f.addVersion()
	f.set(func(f *fakeKMS) { f.state[1] = kmspb.CryptoKeyVersion_DESTROYED })
	got, err := p.Unwrap(ctx, w, []byte("aad"))
	if got != nil || !errors.Is(err, kms.ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured and no key, got %v", err)
	}
	if errors.Is(err, kms.ErrInvalid) {
		t.Fatal("a destroyed version must not be reported as tampering")
	}
}

func TestUnwrapOtherKeyIsNotConfigured(t *testing.T) {
	p, _ := provider(t, newFake())
	w := kms.Wrapped{Provider: "gcpkms", KeyID: testKey + "-other", Version: "1", Ciphertext: []byte{1, 2, 3}}
	if got, err := p.Unwrap(context.Background(), w, []byte("aad")); got != nil || !errors.Is(err, kms.ErrNotConfigured) {
		t.Fatalf("got %v", err)
	}
}

func TestChecksumFailuresAreRejected(t *testing.T) {
	ctx := context.Background()
	pt, aad := []byte("0123456789abcdef"), []byte("aad")

	t.Run("corrupt ciphertext checksum on wrap", func(t *testing.T) {
		f := newFake()
		f.set(func(f *fakeKMS) { f.corruptCT = true })
		p, _ := provider(t, f)
		w, err := p.Wrap(ctx, pt, aad)
		if err == nil || kms.KindOf(err) != kms.Other || len(w.Ciphertext) != 0 {
			t.Fatalf("want Other and no ciphertext, got %v", err)
		}
	})
	t.Run("unverified request checksums on wrap", func(t *testing.T) {
		f := newFake()
		f.set(func(f *fakeKMS) { f.skipVerified = true })
		p, _ := provider(t, f)
		if w, err := p.Wrap(ctx, pt, aad); err == nil || len(w.Ciphertext) != 0 {
			t.Fatalf("accepted an unverified response: %v", err)
		}
	})
	t.Run("corrupt plaintext checksum on unwrap", func(t *testing.T) {
		f := newFake()
		p, _ := provider(t, f)
		w, err := p.Wrap(ctx, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		f.set(func(f *fakeKMS) { f.corruptPT = true })
		got, err := p.Unwrap(ctx, w, aad)
		if err == nil || got != nil || kms.KindOf(err) != kms.Other {
			t.Fatalf("want Other and no key, got %v", err)
		}
	})
	t.Run("response names another key version path", func(t *testing.T) {
		f := newFake()
		f.set(func(f *fakeKMS) {
			f.wrongVersion = "projects/x/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
		})
		p, _ := provider(t, f)
		if _, err := p.Wrap(ctx, pt, aad); err == nil {
			t.Fatal("accepted a response for another key")
		}
	})
	t.Run("malformed version name", func(t *testing.T) {
		for _, n := range []string{
			testKey + "/cryptoKeyVersions/", testKey + "/cryptoKeyVersions/0",
			testKey + "/cryptoKeyVersions/01", testKey + "/cryptoKeyVersions/x", testKey,
		} {
			f := newFake()
			f.set(func(f *fakeKMS) { f.wrongVersion = n })
			p, _ := provider(t, f)
			if _, err := p.Wrap(ctx, pt, aad); err == nil {
				t.Fatalf("accepted version name %q", n)
			}
		}
	})
}

func TestErrorMapping(t *testing.T) {
	ctx := context.Background()
	pt, aad := []byte("0123456789abcdef"), []byte("aad")
	tests := []struct {
		code      codes.Code
		wrap, dec kms.Kind
	}{
		{codes.Unavailable, kms.Unavailable, kms.Unavailable},
		{codes.DeadlineExceeded, kms.Unavailable, kms.Unavailable},
		{codes.ResourceExhausted, kms.Unavailable, kms.Unavailable},
		{codes.Internal, kms.Unavailable, kms.Unavailable},
		{codes.PermissionDenied, kms.Denied, kms.Denied},
		{codes.Unauthenticated, kms.Denied, kms.Denied},
		{codes.InvalidArgument, kms.Other, kms.Invalid},
		{codes.NotFound, kms.NotConfigured, kms.NotConfigured},
		{codes.FailedPrecondition, kms.NotConfigured, kms.NotConfigured},
		{codes.Unknown, kms.Other, kms.Other},
		{codes.Aborted, kms.Other, kms.Other},
	}
	for _, tc := range tests {
		t.Run(tc.code.String(), func(t *testing.T) {
			f := newFake()
			p, _ := provider(t, f)
			w, err := p.Wrap(ctx, pt, aad)
			if err != nil {
				t.Fatal(err)
			}
			f.set(func(f *fakeKMS) {
				f.failWith["Encrypt"] = tc.code
				f.failWith["Decrypt"] = tc.code
				f.failWith["GetCryptoKey"] = tc.code
			})
			_, werr := p.Wrap(ctx, pt, aad)
			got, derr := p.Unwrap(ctx, w, aad)
			_, cerr := p.Current(ctx)
			if kms.KindOf(werr) != tc.wrap || werr == nil {
				t.Fatalf("wrap: want %v, got %v", tc.wrap, werr)
			}
			if kms.KindOf(derr) != tc.dec || derr == nil || got != nil {
				t.Fatalf("unwrap: want %v, got %v", tc.dec, derr)
			}
			if cerr == nil {
				t.Fatal("current: want an error")
			}
			for _, e := range []error{werr, derr, cerr} {
				if strings.Contains(fmt.Sprintf("%v %+v %#v", e, e, e), "secret-looking-sdk-text") {
					t.Fatal("SDK error text leaked into a kms error")
				}
			}
		})
	}
}

func TestErrorsNeverContainValues(t *testing.T) {
	ctx := context.Background()
	p, _ := provider(t, newFake())
	pt := []byte("SECRET-plaintext-0123456789")
	aad := []byte("AAD-value-distinct")
	w, err := p.Wrap(ctx, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	w.Ciphertext[len(w.Ciphertext)-1] ^= 1
	_, err = p.Unwrap(ctx, w, aad)
	if !errors.Is(err, kms.ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	out := fmt.Sprintf("%v %+v %#v", err, err, err)
	for _, s := range []string{string(pt), string(aad), string(w.Ciphertext)} {
		if strings.Contains(out, s) {
			t.Fatal("error output contains a value")
		}
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	ctx := context.Background()
	if _, err := gcpkms.New(ctx, config.KMSGCP{Timeout: time.Second}); err == nil {
		t.Fatal("empty key name accepted")
	}
	if _, err := gcpkms.New(ctx, config.KMSGCP{KeyName: testKey}); err == nil {
		t.Fatal("zero timeout accepted")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"notjson.json": "not json PRIVATE-KEY-TEXT",
		"badtype.json": `{"type":"mystery","private_key":"PRIVATE-KEY-TEXT"}`,
	} {
		path := dir + "/" + name
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := gcpkms.New(ctx, config.KMSGCP{KeyName: testKey, Timeout: time.Second, CredentialsFile: path})
		if err == nil || strings.Contains(err.Error(), "PRIVATE-KEY-TEXT") {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	_, err := gcpkms.New(ctx, config.KMSGCP{KeyName: testKey, Timeout: time.Second, CredentialsFile: dir + "/missing.json"})
	if err == nil || strings.Contains(err.Error(), dir) {
		t.Fatalf("missing file: got %v", err)
	}
}
