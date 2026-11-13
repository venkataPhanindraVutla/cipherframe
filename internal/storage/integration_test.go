//go:build integration

package storage_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
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

// flociImage is the Floci AWS emulator (MIT), the second S3 backend (ADR 0035), pinned by tag and
// digest.
const flociImage = "floci/floci:2.4.0@sha256:5ee85db604c4aa74ac76e07ea5cc83086f37bb472bf3dbb97e34019e48efae9c"

const (
	sourceBucket   = "cipherframe-test-source"
	deliveryBucket = "cipherframe-test-delivery"
	seaweedPort    = "8333/tcp"
	flociPort      = "4566/tcp"
)

// s3server is the one S3 server container shared by every integration test in the package.
type s3server struct {
	// internalHost and publicHost are two different spellings of the container's address, so the
	// test can tell the internal endpoint from the public one. On a plain Docker host they are
	// 127.0.0.1 and localhost; when the tests run inside a container (TESTCONTAINERS_HOST_OVERRIDE,
	// build/test-media.sh) they are the IP address of that host name and the name itself.
	internalHost string
	publicHost   string
	port         string
	accessKey    string
	secretKey    string
}

var srv *s3server

func TestMain(m *testing.M) {
	ctx := context.Background()
	s, c, err := startServer(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration setup failed:", err)
		if c != nil {
			_ = c.Terminate(ctx)
		}
		os.Exit(1)
	}
	srv = s
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

// startServer starts the S3 backend the tests run against (ADR 0035): SeaweedFS by default, Floci
// when CIPHERFRAME_TEST_S3_BACKEND=floci.
func startServer(ctx context.Context) (*s3server, testcontainers.Container, error) {
	switch b := os.Getenv("CIPHERFRAME_TEST_S3_BACKEND"); b {
	case "", "seaweedfs":
		return startSeaweed(ctx)
	case "floci":
		return startFloci(ctx)
	default:
		return nil, nil, fmt.Errorf("unknown CIPHERFRAME_TEST_S3_BACKEND %q (want seaweedfs or floci)", b)
	}
}

// startSeaweed runs SeaweedFS with its S3 gateway. The gateway only verifies signatures when it has
// identities, so a throwaway access key is generated per run and written to the identities file
// (-s3.config). Master, volume server and S3 gateway run in one process ("server -s3").
func startSeaweed(ctx context.Context) (*s3server, testcontainers.Container, error) {
	access, secret := "AK"+strings.ToUpper(randomHex(8)), randomHex(20)
	identities := fmt.Sprintf(`{"identities":[{"name":"cipherframe-test","credentials":[{"accessKey":%q,"secretKey":%q}],`+
		`"actions":["Admin","Read","Write","List","Tagging"]}]}`, access, secret)
	return start(ctx, testcontainers.ContainerRequest{
		Image:        seaweedImage,
		ExposedPorts: []string{seaweedPort},
		Cmd:          []string{"server", "-dir=/data", "-ip.bind=0.0.0.0", "-s3", "-s3.port=8333", "-s3.config=/etc/seaweedfs/s3.json"},
		Files: []testcontainers.ContainerFile{{
			Reader:            strings.NewReader(identities),
			ContainerFilePath: "/etc/seaweedfs/s3.json",
			FileMode:          0o644,
		}},
		WaitingFor: wait.ForListeningPort(seaweedPort).WithStartupTimeout(3 * time.Minute),
	}, seaweedPort, access, secret)
}

// startFloci runs Floci with signature checks on: without them it accepts any credentials and any
// presigned URL, and the security tests below would pass for the wrong reason. Floci's built-in
// credentials are the access key "test" with the secret "test".
func startFloci(ctx context.Context) (*s3server, testcontainers.Container, error) {
	return start(ctx, testcontainers.ContainerRequest{
		Image:        flociImage,
		ExposedPorts: []string{flociPort},
		Env:          map[string]string{"FLOCI_AUTH_VALIDATE_SIGNATURES": "true"},
		WaitingFor:   wait.ForHTTP("/_localstack/health").WithPort(flociPort).WithStartupTimeout(3 * time.Minute),
	}, flociPort, "test", "test")
}

// start runs the container, finds the host forms it is reachable at and creates the test buckets.
func start(ctx context.Context, req testcontainers.ContainerRequest, s3Port, access, secret string) (*s3server, testcontainers.Container, error) {
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		return nil, c, fmt.Errorf("start container: %w", err)
	}
	port, err := c.MappedPort(ctx, s3Port)
	if err != nil {
		return nil, c, fmt.Errorf("mapped port: %w", err)
	}
	host, err := c.Host(ctx)
	if err != nil {
		return nil, c, fmt.Errorf("container host: %w", err)
	}
	s := &s3server{internalHost: "127.0.0.1", publicHost: "localhost", port: port.Port(), accessKey: access, secretKey: secret}
	if host != "localhost" && host != "127.0.0.1" {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addrs) == 0 {
			return nil, c, fmt.Errorf("resolve %s: %w", host, err)
		}
		s.internalHost, s.publicHost = addrs[0].IP.String(), host
	}
	if err := s.createBuckets(ctx, sourceBucket, deliveryBucket); err != nil {
		return nil, c, err
	}
	return s, c, nil
}

// createBuckets is test setup only: bucket creation is outside the storage port. The master and
// volume server need a moment after the S3 port opens, so it retries.
func (s *s3server) createBuckets(ctx context.Context, names ...string) error {
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

func (s *s3server) internalURL() string { return "http://" + s.internalHost + ":" + s.port }
func (s *s3server) publicURL() string   { return "http://" + s.publicHost + ":" + s.port }

// cfg returns a configuration whose internal and public endpoints use different host forms.
func (s *s3server) cfg() config.S3 {
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
	b, err := storage.New(context.Background(), srv.cfg())
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
	if u.Host != srv.publicHost+":"+srv.port {
		t.Fatalf("presigned host = %q, want the public endpoint %s:%s", u.Host, srv.publicHost, srv.port)
	}
	if body := fetch(t, req.URL); body != "public" {
		t.Fatalf("GET through the public host returned %q", body)
	}

	// The signature covers the host: the same URL aimed at the internal host must be refused.
	u.Host = srv.internalHost + ":" + srv.port
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
	cfg := srv.cfg()
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
	cfg := srv.cfg()
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
	cfg := srv.cfg()
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
