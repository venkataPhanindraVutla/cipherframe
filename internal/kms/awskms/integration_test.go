//go:build integration && !nokms_aws

package awskms_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awskmssdk "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/awskms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
)

// motoImage is the moto server (Apache-2.0), pinned by tag and digest (ADR 0023). The digest is the
// multi-architecture manifest list of the tag.
const motoImage = "motoserver/moto:5.2.5@sha256:59a1965d845249b04def37a0e2565f9cc6c44543cb89b68e90f28f344b3b0d1a"

const (
	motoRegion = "eu-west-1"
	motoKey    = "test" // moto accepts any credentials
)

// moto is the one moto container shared by every integration test in the package. It starts on
// first use, so the opt-in real-AWS test needs no Docker.
var moto struct {
	once      sync.Once
	container testcontainers.Container
	endpoint  string
	err       error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if moto.container != nil {
		_ = moto.container.Terminate(context.Background())
	}
	os.Exit(code)
}

func motoEndpoint(t *testing.T) string {
	t.Helper()
	moto.once.Do(func() {
		ctx := context.Background()
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        motoImage,
				ExposedPorts: []string{"5000/tcp"},
				WaitingFor:   wait.ForHTTP("/moto-api/").WithPort("5000/tcp").WithStartupTimeout(2 * time.Minute),
			},
			Started: true,
		})
		if c != nil {
			moto.container = c
		}
		if err != nil {
			moto.err = err
			return
		}
		host, err := c.Host(ctx)
		if err != nil {
			moto.err = err
			return
		}
		port, err := c.MappedPort(ctx, "5000/tcp")
		if err != nil {
			moto.err = err
			return
		}
		moto.endpoint = "http://" + net.JoinHostPort(host, port.Port())
	})
	if moto.err != nil {
		t.Fatalf("moto setup failed: %v", moto.err)
	}
	return moto.endpoint
}

// admin is a KMS client for creating keys and aliases directly.
func admin(endpoint string) *awskmssdk.Client {
	return awskmssdk.New(awskmssdk.Options{
		Region:       motoRegion,
		Credentials:  credentials.NewStaticCredentialsProvider(motoKey, motoKey, ""),
		BaseEndpoint: aws.String(endpoint),
	})
}

// newKey creates a symmetric key and returns its ARN.
func newKey(t *testing.T, endpoint string) string {
	t.Helper()
	out, err := admin(endpoint).CreateKey(context.Background(), &awskmssdk.CreateKeyInput{})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}
	return aws.ToString(out.KeyMetadata.Arn)
}

func motoConfig(endpoint, keyID string) config.KMSAWS {
	return config.KMSAWS{
		KeyID:           keyID,
		Region:          motoRegion,
		Endpoint:        endpoint,
		AccessKeyID:     config.NewStaticCredential(motoKey),
		SecretAccessKey: config.NewStaticCredential(motoKey),
		Timeout:         5 * time.Second,
	}
}

func provider(t *testing.T, cfg config.KMSAWS) *awskms.Provider {
	t.Helper()
	p, err := awskms.New(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// motoProvider adapts one moto behaviour for the conformance suite. When Decrypt is pinned to a key
// that is not the one named inside the ciphertext, which is what a flipped byte in the blob's key
// id looks like, real AWS answers IncorrectKeyException (Invalid) while moto answers
// AccessDeniedException (Denied). The adapter reports that moto answer as Invalid so the tamper
// test can run; the provider's own mapping (AccessDeniedException is Denied) is covered by the unit
// tests and stays unchanged.
type motoProvider struct{ *awskms.Provider }

func (m motoProvider) Unwrap(ctx context.Context, w kms.Wrapped, aad []byte) ([]byte, error) {
	b, err := m.Provider.Unwrap(ctx, w, aad)
	if err != nil && kms.KindOf(err) == kms.Denied {
		return nil, kms.New(kms.Invalid, awskms.Name, "unwrap", "moto answered AccessDeniedException for a mismatched key")
	}
	return b, err
}

// proxy is a TCP forwarder in front of moto. Closing it makes the endpoint a closed port, which is
// how the suite simulates an outage; restoring it listens on the same address again.
type proxy struct {
	addr   string
	target string

	mu    sync.Mutex
	ln    net.Listener
	conns []net.Conn
}

func newProxy(t *testing.T, target string) *proxy {
	t.Helper()
	p := &proxy{target: target}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.addr = ln.Addr().String()
	p.serve(ln)
	t.Cleanup(p.stop)
	return p
}

func (p *proxy) serve(ln net.Listener) {
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", p.target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, up)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
}

func (p *proxy) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

func (p *proxy) restart() error {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", p.addr)
	if err != nil {
		return err
	}
	p.serve(ln)
	return nil
}

// TestMotoConformance runs the provider conformance suite against moto. moto does not rotate key
// material visibly, so mixed key versions are covered the way a key change looks to a caller: the
// rotated provider has another KMS key as its current key, and must still unwrap what the first
// key wrapped.
func TestMotoConformance(t *testing.T) {
	endpoint := motoEndpoint(t)
	keyA, keyB := newKey(t, endpoint), newKey(t, endpoint)

	var mu sync.Mutex
	proxies := map[kms.Provider]*proxy{}

	kmstest.Run(t,
		func(t *testing.T) kms.Provider {
			px := newProxy(t, endpoint[len("http://"):])
			p := motoProvider{provider(t, motoConfig("http://"+px.addr, keyA))}
			mu.Lock()
			proxies[p] = px
			mu.Unlock()
			return p
		},
		kmstest.WithRotated(func(t *testing.T) kms.Provider {
			return motoProvider{provider(t, motoConfig(endpoint, keyB))}
		}),
		kmstest.WithOutage(func(t *testing.T, p kms.Provider) func() {
			mu.Lock()
			px := proxies[p]
			mu.Unlock()
			px.stop()
			return func() {
				if err := px.restart(); err != nil {
					t.Errorf("restoring the endpoint: %v", err)
				}
			}
		}),
	)
}

// TestMotoAliasResolvesToARN checks the identity rules: an alias resolves to the key ARN, wraps
// record the ARN, and unwrap works from the ARN alone, so it survives the alias being repointed.
func TestMotoAliasResolvesToARN(t *testing.T) {
	endpoint := motoEndpoint(t)
	ctx := context.Background()
	keyA, keyB := newKey(t, endpoint), newKey(t, endpoint)
	alias := fmt.Sprintf("alias/cipherframe-%d", time.Now().UnixNano())
	if _, err := admin(endpoint).CreateAlias(ctx, &awskmssdk.CreateAliasInput{AliasName: aws.String(alias), TargetKeyId: aws.String(keyA)}); err != nil {
		t.Fatal(err)
	}

	p := provider(t, motoConfig(endpoint, alias))
	ref, err := p.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ref.KeyID != keyA || ref.Version != awskms.Version {
		t.Fatalf("Current = %+v, want the ARN of key A", ref)
	}
	aad := []byte("aad")
	w, err := p.Wrap(ctx, []byte("0123456789abcdef"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if w.KeyID != keyA {
		t.Fatalf("wrapped key records %q, want the ARN of key A", w.KeyID)
	}

	// Repoint the alias: new wraps use key B, the old wrap still opens under key A.
	if _, err := admin(endpoint).UpdateAlias(ctx, &awskmssdk.UpdateAliasInput{AliasName: aws.String(alias), TargetKeyId: aws.String(keyB)}); err != nil {
		t.Fatal(err)
	}
	w2, err := p.Wrap(ctx, []byte("fedcba9876543210"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if w2.KeyID != keyB {
		t.Fatalf("after the alias moved, new wraps record %q, want the ARN of key B", w2.KeyID)
	}
	for name, c := range map[string]struct {
		w  kms.Wrapped
		pt string
	}{"old": {w, "0123456789abcdef"}, "new": {w2, "fedcba9876543210"}} {
		got, err := p.Unwrap(ctx, c.w, aad)
		if err != nil || string(got) != c.pt {
			t.Fatalf("%s wrap did not unwrap: %v", name, err)
		}
	}
}

// TestMotoPinnedKeyIsEnforced checks that a ciphertext does not open under another key's ARN.
func TestMotoPinnedKeyIsEnforced(t *testing.T) {
	endpoint := motoEndpoint(t)
	keyA, keyB := newKey(t, endpoint), newKey(t, endpoint)
	p := provider(t, motoConfig(endpoint, keyA))
	w, err := p.Wrap(context.Background(), []byte("0123456789abcdef"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	w.KeyID = keyB
	got, err := p.Unwrap(context.Background(), w, []byte("aad"))
	if err == nil || got != nil {
		t.Fatal("a ciphertext opened under a key it was not wrapped by")
	}
	// Real AWS answers a mismatched pinned key with IncorrectKeyException (Invalid); moto answers
	// AccessDeniedException (Denied). Either way no key is returned.
	if k := kms.KindOf(err); k != kms.Invalid && k != kms.NotConfigured && k != kms.Denied {
		t.Fatalf("kind = %v", k)
	}
}

// TestMotoDisabledKey checks that Current reports a disabled key as not configured.
func TestMotoDisabledKey(t *testing.T) {
	endpoint := motoEndpoint(t)
	ctx := context.Background()
	key := newKey(t, endpoint)
	p := provider(t, motoConfig(endpoint, key))
	if _, err := admin(endpoint).DisableKey(ctx, &awskmssdk.DisableKeyInput{KeyId: aws.String(key[strings.LastIndex(key, "/")+1:])}); err != nil { // moto's DisableKey wants the bare key id
		t.Fatal(err)
	}
	// moto keeps encrypting and decrypting under a disabled key, which real AWS refuses with
	// DisabledException (NotConfigured, unit-tested), so only Current is checked here.
	if _, err := p.Current(ctx); !errors.Is(err, kms.ErrNotConfigured) {
		t.Errorf("Current: want ErrNotConfigured, got %v", err)
	}
}

// TestMotoMissingKey checks that an unknown key is reported as not configured.
func TestMotoMissingKey(t *testing.T) {
	endpoint := motoEndpoint(t)
	p := provider(t, motoConfig(endpoint, "alias/does-not-exist"))
	if _, err := p.Current(context.Background()); !errors.Is(err, kms.ErrNotConfigured) {
		t.Errorf("Current: want ErrNotConfigured, got %v", err)
	}
	if _, err := p.Wrap(context.Background(), []byte("0123456789abcdef"), []byte("aad")); !errors.Is(err, kms.ErrNotConfigured) {
		t.Errorf("Wrap: want ErrNotConfigured, got %v", err)
	}
}

// TestRealAWSKMS runs the conformance suite against a real AWS KMS key. It is opt-in: set
// CIPHERFRAME_TEST_AWS_KMS_KEY_ID (a key ARN, alias ARN or alias/name of a symmetric key with
// encrypt, decrypt and DescribeKey permissions) and CIPHERFRAME_TEST_AWS_REGION. Credentials come
// from the default chain. It covers neither mixed versions nor outages.
func TestRealAWSKMS(t *testing.T) {
	keyID, region := os.Getenv("CIPHERFRAME_TEST_AWS_KMS_KEY_ID"), os.Getenv("CIPHERFRAME_TEST_AWS_REGION")
	if keyID == "" || region == "" {
		t.Skip("set CIPHERFRAME_TEST_AWS_KMS_KEY_ID and CIPHERFRAME_TEST_AWS_REGION to run against real AWS KMS")
	}
	cfg := config.KMSAWS{
		KeyID:           keyID,
		Region:          region,
		AccessKeyID:     config.NewStaticCredential(""),
		SecretAccessKey: config.NewStaticCredential(""),
		Timeout:         15 * time.Second,
	}
	kmstest.Run(t, func(t *testing.T) kms.Provider { return provider(t, cfg) })
}
