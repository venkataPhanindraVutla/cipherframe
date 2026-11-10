//go:build integration

package storage_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/storagetest"
)

// seaweedImage is pinned (ADR 0014). Keep it in step with Docker Compose (M1-8).
const seaweedImage = "chrislusf/seaweedfs:4.53"

const (
	sourceBucket   = "cipherframe-test-source"
	deliveryBucket = "cipherframe-test-delivery"
	s3Port         = "8333/tcp"
)

// seaweed is the one SeaweedFS container shared by every integration test in the package.
type seaweed struct {
	port      string
	accessKey string
	secretKey string
}

var sw *seaweed

func TestMain(m *testing.M) {
	ctx := context.Background()
	s, c, err := startSeaweed(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration setup failed:", err)
		if c != nil {
			_ = c.Terminate(ctx)
		}
		os.Exit(1)
	}
	sw = s
	code := m.Run()
	_ = c.Terminate(ctx)
	os.Exit(code)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// startSeaweed runs SeaweedFS with its S3 gateway. The gateway only verifies signatures when it has
// identities, so a throwaway access key is generated per run and written to the identities file
// (-s3.config). Master, volume server and S3 gateway run in one process ("server -s3").
func startSeaweed(ctx context.Context) (*seaweed, testcontainers.Container, error) {
	access, secret := "AK"+strings.ToUpper(randomHex(8)), randomHex(20)
	identities := fmt.Sprintf(`{"identities":[{"name":"cipherframe-test","credentials":[{"accessKey":%q,"secretKey":%q}],`+
		`"actions":["Admin","Read","Write","List","Tagging"]}]}`, access, secret)

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        seaweedImage,
			ExposedPorts: []string{s3Port},
			Cmd:          []string{"server", "-dir=/data", "-ip.bind=0.0.0.0", "-s3", "-s3.port=8333", "-s3.config=/etc/seaweedfs/s3.json"},
			Files: []testcontainers.ContainerFile{{
				Reader:            strings.NewReader(identities),
				ContainerFilePath: "/etc/seaweedfs/s3.json",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForListeningPort(s3Port).WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		return nil, c, fmt.Errorf("start container: %w", err)
	}
	port, err := c.MappedPort(ctx, s3Port)
	if err != nil {
		return nil, c, fmt.Errorf("mapped port: %w", err)
	}
	s := &seaweed{port: port.Port(), accessKey: access, secretKey: secret}
	if err := s.createBuckets(ctx, sourceBucket, deliveryBucket); err != nil {
		return nil, c, err
	}
	return s, c, nil
}

// createBuckets is test setup only: bucket creation is outside the storage port. The master and
// volume server need a moment after the S3 port opens, so it retries.
func (s *seaweed) createBuckets(ctx context.Context, names ...string) error {
	client := s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(s.internalURL()),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(s.accessKey, s.secretKey, ""),
	})
	deadline := time.Now().Add(90 * time.Second)
	for _, name := range names {
		for {
			_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(name)})
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
			time.Sleep(time.Second)
		}
	}
	return nil
}

func (s *seaweed) internalURL() string { return "http://127.0.0.1:" + s.port }
func (s *seaweed) publicURL() string   { return "http://localhost:" + s.port }

// cfg returns a configuration whose internal and public endpoints use different host forms.
func (s *seaweed) cfg() config.S3 {
	return config.S3{
		Endpoint:        s.internalURL(),
		PublicEndpoint:  s.publicURL(),
		Region:          "us-east-1",
		ForcePathStyle:  true,
		SourceBucket:    sourceBucket,
		DeliveryBucket:  deliveryBucket,
		AccessKeyID:     config.NewStaticCredential(s.accessKey),
		SecretAccessKey: config.NewStaticCredential(s.secretKey),
	}
}

func newBuckets(t *testing.T) *storage.Buckets {
	t.Helper()
	b, err := storage.New(context.Background(), sw.cfg())
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	return b
}

func TestConformanceSourceBucket(t *testing.T) {
	storagetest.Run(t, func(t *testing.T) storage.Store { return newBuckets(t).Source })
}

func TestConformanceDeliveryBucket(t *testing.T) {
	storagetest.Run(t, func(t *testing.T) storage.Store { return newBuckets(t).Delivery })
}

func TestBucketsAreIsolated(t *testing.T) {
	b := newBuckets(t)
	ctx := context.Background()
	key := "isolation/" + randomHex(6)
	if err := b.Source.Put(ctx, key, strings.NewReader("s"), 1, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Source.DeleteBatch(ctx, []string{key}) })
	if _, err := b.Delivery.Head(ctx, key); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("an object in the source bucket is visible in the delivery bucket: %v", err)
	}
}

// The public client signs for the public host. The internal endpoint (127.0.0.1) is not reachable
// from a browser in a real deployment, so a URL signed for it would be useless there.
func TestPresignedURLUsesPublicEndpoint(t *testing.T) {
	b := newBuckets(t)
	ctx := context.Background()
	key := "public-host/" + randomHex(6)
	if err := b.Delivery.Put(ctx, key, strings.NewReader("public"), 6, "text/plain"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Delivery.DeleteBatch(ctx, []string{key}) })

	req, err := b.Delivery.PresignGet(ctx, key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "localhost:"+sw.port {
		t.Fatalf("presigned host = %q, want the public endpoint localhost:%s", u.Host, sw.port)
	}
	if body := fetch(t, req.URL); body != "public" {
		t.Fatalf("GET through the public host returned %q", body)
	}

	// The signature covers the host: the same URL aimed at the internal host must be refused.
	u.Host = "127.0.0.1:" + sw.port
	resp := do(t, u.String())
	if resp != http.StatusForbidden {
		t.Fatalf("URL re-aimed at the internal host: status %d, want 403 (signature covers the host)", resp)
	}
}

func fetch(t *testing.T, u string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", errors.Unwrap(err))
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status %d", resp.StatusCode)
	}
	return string(b)
}

func do(t *testing.T, u string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", errors.Unwrap(err))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestWrongCredentialsArePermissionDenied(t *testing.T) {
	cfg := sw.cfg()
	cfg.SecretAccessKey = config.NewStaticCredential(randomHex(20))
	b, err := storage.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Source.Head(context.Background(), "anything")
	if !errors.Is(err, storage.ErrPermissionDenied) {
		t.Fatalf("bad secret: %v", err)
	}
	if errors.Is(err, storage.ErrNotFound) {
		t.Fatal("a credential failure must never look like NotFound")
	}
}

func TestMissingBucketIsNotNotFound(t *testing.T) {
	cfg := sw.cfg()
	s, err := storage.NewStore(context.Background(), cfg, "no-such-bucket-"+randomHex(4), keys.Source)
	if err != nil {
		t.Fatal(err)
	}
	// HEAD cannot tell the two apart: S3 sends no body on HEAD, so a missing bucket and a missing
	// object are both a bare 404 and Head reports NotFound for both. Operations with a response body
	// (Get, List, Put) carry the NoSuchBucket code and are not NotFound.
	_, _, err = s.Get(context.Background(), "k", nil)
	if err == nil || errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("get from a missing bucket: %v", err)
	}
}

func TestUnreachableEndpointIsUnavailable(t *testing.T) {
	cfg := sw.cfg()
	cfg.Endpoint = "http://127.0.0.1:1" // nothing listens on port 1
	cfg.PublicEndpoint = cfg.Endpoint
	b, err := storage.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = b.Source.Head(ctx, "k")
	if !errors.Is(err, storage.ErrUnavailable) {
		t.Fatalf("connection refused: %v", err)
	}
}

func TestDeadlineIsTimeout(t *testing.T) {
	b := newBuckets(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	_, err := b.Source.Head(ctx, "k")
	if !errors.Is(err, storage.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired context: %v", err)
	}
}

// TestRealS3 runs the suite against a real S3 or R2 bucket. It is opt-in: it runs only when all four
// variables are set. CIPHERFRAME_TEST_S3_REGION (default us-east-1, use "auto" for R2) and
// CIPHERFRAME_TEST_S3_PATH_STYLE=true are optional. The credentials need read, write, list and
// delete on the bucket; the suite only touches keys under "conformance/".
func TestRealS3(t *testing.T) {
	endpoint := os.Getenv("CIPHERFRAME_TEST_S3_ENDPOINT")
	bucket := os.Getenv("CIPHERFRAME_TEST_S3_BUCKET")
	access := os.Getenv("CIPHERFRAME_TEST_S3_ACCESS_KEY_ID")
	secret := os.Getenv("CIPHERFRAME_TEST_S3_SECRET_ACCESS_KEY")
	if endpoint == "" || bucket == "" || access == "" || secret == "" {
		t.Skip("set CIPHERFRAME_TEST_S3_ENDPOINT, _BUCKET, _ACCESS_KEY_ID and _SECRET_ACCESS_KEY to run against real S3 or R2")
	}
	region := os.Getenv("CIPHERFRAME_TEST_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	cfg := config.S3{
		Endpoint:        endpoint,
		PublicEndpoint:  endpoint,
		Region:          region,
		ForcePathStyle:  os.Getenv("CIPHERFRAME_TEST_S3_PATH_STYLE") == "true",
		AccessKeyID:     config.NewStaticCredential(access),
		SecretAccessKey: config.NewStaticCredential(secret),
	}
	storagetest.Run(t, func(t *testing.T) storage.Store {
		s, err := storage.NewStore(context.Background(), cfg, bucket, keys.Delivery)
		if err != nil {
			t.Fatalf("storage.NewStore: %v", err)
		}
		return s
	})
}
