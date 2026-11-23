package cdn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // the providers define RSA-SHA1 and HMAC-SHA1
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
)

const testKey = "t/tnt/a/ast/v/original/720p/seg_00001.m4s"

var testExpiry = time.Unix(1800000000, 999_000_000) // the fraction is dropped

func testRSA(t *testing.T) (*rsa.PrivateKey, []byte, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, pkcs1, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// The expected value is built here from the provider's rules, not by calling the signer's helpers.
func TestCloudFrontSign(t *testing.T) {
	k, pkcs1, pkcs8 := testRSA(t)
	for name, pemBytes := range map[string][]byte{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		s, err := NewCloudFront("https://cdn.example.com", "K2JCJMDEHXQW5F", pemBytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := s.Sign(testKey, testExpiry)
		if err != nil {
			t.Fatal(err)
		}
		resource := "https://cdn.example.com/" + testKey
		u, err := url.Parse(got)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		if u.Scheme+"://"+u.Host+u.Path != resource || q.Get("Expires") != "1800000000" || q.Get("Key-Pair-Id") != "K2JCJMDEHXQW5F" || len(q) != 3 {
			t.Fatalf("%s: unexpected URL shape", name)
		}
		// The canned policy, byte for byte as CloudFront documents it (no whitespace).
		policy := `{"Statement":[{"Resource":"` + resource + `","Condition":{"DateLessThan":{"AWS:EpochTime":1800000000}}}]}`
		digest := sha1.Sum([]byte(policy)) //nolint:gosec // see the import
		// CloudFront's alphabet: + - , = _ , / ~ . Undo it and verify the RSA-SHA1 signature.
		raw := q.Get("Signature")
		if strings.ContainsAny(raw, "+=/") {
			t.Fatalf("%s: the signature uses the standard base64 alphabet", name)
		}
		std := strings.Map(func(r rune) rune {
			switch r {
			case '-':
				return '+'
			case '_':
				return '='
			case '~':
				return '/'
			}
			return r
		}, raw)
		sig, err := base64.StdEncoding.DecodeString(std)
		if err != nil {
			t.Fatal(err)
		}
		if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA1, digest[:], sig); err != nil {
			t.Fatalf("%s: the signature does not verify over the canned policy: %v", name, err)
		}
		// PKCS#1 v1.5 is deterministic, so signing again gives the same bytes.
		again, _ := rsa.SignPKCS1v15(nil, k, crypto.SHA1, digest[:])
		if string(again) != string(sig) {
			t.Fatalf("%s: not the signature of the canned policy", name)
		}
	}
}

func TestCloudFrontKeyErrors(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately too small: the test checks it is refused
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"not pem":   "test-fixture-not-a-key",
		"too small": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)})),
		"bad body":  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("test-fixture-garbage")})),
		"wrong typ": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})),
	} {
		_, err := NewCloudFront("https://cdn.example.com", "K1", []byte(in))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "test-fixture") {
			t.Errorf("%s: the error quotes the key", name)
		}
	}
}

// The signature below was computed outside Go with openssl:
//
//	echo -n "$URL" | openssl dgst -sha1 -mac HMAC -macopt hexkey:000102030405060708090a0b0c0d0e0f -binary | base64 | tr '+/' '-_'
func TestCloudCDNKnownAnswer(t *testing.T) {
	// The key is 16 bytes, 00 01 02 ... 0f, in URL-safe base64.
	for _, key := range []string{"AAECAwQFBgcICQoLDA0ODw==\n", "AAECAwQFBgcICQoLDA0ODw"} {
		s, err := NewCloudCDN("https://media.example.com/", "test-key", []byte(key))
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Sign(testKey, testExpiry)
		if err != nil {
			t.Fatal(err)
		}
		const want = "https://media.example.com/" + testKey + "?Expires=1800000000&KeyName=test-key&Signature=-0xAUsXZmfOWTr9DIiKI6a8vuzg="
		if got != want {
			t.Fatalf("got a different URL than the known answer: %s", redact(got))
		}
	}
}

// redact keeps a failing test from printing a signed URL.
func redact(u string) string { return strings.SplitN(u, "?", 2)[0] + "?[redacted]" }

func TestCloudCDNKeyErrors(t *testing.T) {
	for name, in := range map[string]string{
		"not base64": "test-fixture-!!!!",
		"too short":  base64.URLEncoding.EncodeToString(make([]byte, 8)),
		"too long":   base64.URLEncoding.EncodeToString(make([]byte, 32)),
	} {
		if _, err := NewCloudCDN("https://m.example.com", "k", []byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSignRefusesUnsafeKeys(t *testing.T) {
	_, pkcs1, _ := testRSA(t)
	cf, _ := NewCloudFront("https://cdn.example.com", "K1", pkcs1)
	cc, _ := NewCloudCDN("https://m.example.com", "k", []byte("AAECAwQFBgcICQoLDA0ODw=="))
	for _, key := range []string{"", "/abs", "a/../b", "a b", "a?x=1", "a#b", "a\"b", "é"} {
		for _, s := range []Signer{cf, cc} {
			if _, err := s.Sign(key, testExpiry); !errors.Is(err, ErrBadKey) {
				t.Errorf("key %q: %v", key, err)
			}
		}
	}
}

func TestNewSignerFromConfig(t *testing.T) {
	_, pkcs1, _ := testRSA(t)
	files := map[string][]byte{"/k/cf": pkcs1, "/k/cc": []byte("AAECAwQFBgcICQoLDA0ODw==")}
	read := func(p string) ([]byte, error) {
		if b, ok := files[p]; ok {
			return b, nil
		}
		return nil, errors.New("no such file")
	}
	for _, c := range []config.CDN{
		{Provider: config.CDNCloudFront, BaseURL: "https://cdn.example.com", KeyID: "K1", SigningKeyFile: "/k/cf"},
		{Provider: config.CDNCloudCDN, BaseURL: "https://m.example.com", KeyID: "k", SigningKeyFile: "/k/cc"},
	} {
		s, err := newSigner(c, read)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Sign(testKey, testExpiry); err != nil {
			t.Fatal(err)
		}
	}
	// A missing file and a key of the wrong provider fail at startup and name the setting only.
	for _, c := range []config.CDN{
		{Provider: config.CDNCloudFront},
		{Provider: config.CDNCloudFront, SigningKeyFile: "/k/missing"},
		{Provider: config.CDNCloudFront, SigningKeyFile: "/k/cc"},
		{Provider: config.CDNCloudCDN, SigningKeyFile: "/k/cf"},
	} {
		_, err := newSigner(c, read)
		if err == nil || !strings.Contains(err.Error(), config.EnvCDNSigningKeyFile) {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

type fakeInvalidations struct {
	mu   sync.Mutex
	in   []*cloudfront.CreateInvalidationInput
	fail error
}

func (f *fakeInvalidations) CreateInvalidation(_ context.Context, in *cloudfront.CreateInvalidationInput, _ ...func(*cloudfront.Options)) (*cloudfront.CreateInvalidationOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.in = append(f.in, in)
	return &cloudfront.CreateInvalidationOutput{}, f.fail
}

func TestCloudFrontPurge(t *testing.T) {
	f := &fakeInvalidations{}
	p := NewCloudFrontPurger(f, "E2EXAMPLE1ABCD")
	if err := p.Purge(context.Background(), "t/tnt/a/ast/"); err != nil {
		t.Fatal(err)
	}
	if err := p.Purge(context.Background(), "t/tnt/a/ast/"); err != nil {
		t.Fatal(err)
	}
	if len(f.in) != 2 {
		t.Fatalf("%d calls", len(f.in))
	}
	in := f.in[0]
	if *in.DistributionId != "E2EXAMPLE1ABCD" || *in.InvalidationBatch.Paths.Quantity != 1 || in.InvalidationBatch.Paths.Items[0] != "/t/tnt/a/ast/*" {
		t.Fatalf("unexpected invalidation: %+v", in.InvalidationBatch.Paths)
	}
	if *in.InvalidationBatch.CallerReference != *f.in[1].InvalidationBatch.CallerReference {
		t.Fatal("a retry must reuse the caller reference")
	}
	f.fail = errors.New("throttled")
	if err := p.Purge(context.Background(), "t/tnt/a/ast/"); err == nil {
		t.Fatal("the API error was swallowed")
	}
	for _, bad := range []string{"", "t/tnt", "/t/tnt/", "../x/", "t/*/"} {
		if err := p.Purge(context.Background(), bad); !errors.Is(err, ErrBadPrefix) {
			t.Errorf("prefix %q: %v", bad, err)
		}
	}
}

func TestCloudCDNPurge(t *testing.T) {
	var gotPath, gotBody string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotPath, gotBody = r.Method+" "+r.URL.Path, string(b)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	p := NewCloudCDNPurger(srv.Client(), srv.URL+"/", "my-project", "cipherframe-map")
	if err := p.Purge(context.Background(), "t/tnt/a/ast/"); err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil || body["path"] != "/t/tnt/a/ast/*" || len(body) != 1 {
		t.Fatalf("body %q", gotBody)
	}
	if gotPath != "POST /compute/v1/projects/my-project/global/urlMaps/cipherframe-map/invalidateCache" {
		t.Fatalf("path %q", gotPath)
	}
	status = http.StatusTooManyRequests
	if err := p.Purge(context.Background(), "t/tnt/a/ast/"); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("a refused request must fail: %v", err)
	}
	if err := p.Purge(context.Background(), "t/tnt"); !errors.Is(err, ErrBadPrefix) {
		t.Fatalf("bad prefix: %v", err)
	}
}
