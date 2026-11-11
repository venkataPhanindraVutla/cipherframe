//go:build integration

package storagetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
)

// SeaweedImage is pinned (ADR 0014). Keep it in step with Docker Compose.
const SeaweedImage = "chrislusf/seaweedfs:4.53"

const (
	// SourceBucket and DeliveryBucket are the bucket names Seaweed creates for tests.
	SourceBucket   = "cipherframe-test-source"
	DeliveryBucket = "cipherframe-test-delivery"
	s3Port         = "8333/tcp"
)

// Seaweed is a SeaweedFS container with its S3 gateway and the two buckets, shared by every test
// of a test binary. Start it lazily with Shared so a package pays for it only when a test needs it.
type Seaweed struct {
	host      string
	port      string
	accessKey string
	secretKey string
	container testcontainers.Container
}

var (
	sharedOnce sync.Once
	shared     *Seaweed
	sharedErr  error
)

// Shared starts the container on first use and returns it. Call Terminate from TestMain after the
// tests have run.
func Shared(t testing.TB) *Seaweed {
	t.Helper()
	sharedOnce.Do(func() { shared, sharedErr = start(context.Background()) })
	if sharedErr != nil {
		t.Fatalf("start SeaweedFS: %v", sharedErr)
	}
	return shared
}

// Terminate stops the shared container, if it was started.
func Terminate() {
	if shared != nil && shared.container != nil {
		_ = shared.container.Terminate(context.Background())
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func start(ctx context.Context) (*Seaweed, error) {
	access, secret := "AK"+strings.ToUpper(randomHex(8)), randomHex(20)
	identities := fmt.Sprintf(`{"identities":[{"name":"cipherframe-test","credentials":[{"accessKey":%q,"secretKey":%q}],`+
		`"actions":["Admin","Read","Write","List","Tagging"]}]}`, access, secret)

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        SeaweedImage,
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
		return nil, fmt.Errorf("start container: %w", err)
	}
	port, err := c.MappedPort(ctx, s3Port)
	if err != nil {
		_ = c.Terminate(ctx)
		return nil, fmt.Errorf("mapped port: %w", err)
	}
	// The container's host is "localhost" on a plain Docker host, and whatever
	// TESTCONTAINERS_HOST_OVERRIDE names when the tests themselves run inside a container
	// (host.docker.internal; see CONTRIBUTING.md, "Media and pipeline tests").
	host, err := c.Host(ctx)
	if err != nil {
		_ = c.Terminate(ctx)
		return nil, fmt.Errorf("container host: %w", err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	s := &Seaweed{host: host, port: port.Port(), accessKey: access, secretKey: secret, container: c}
	if err := s.createBuckets(ctx, SourceBucket, DeliveryBucket); err != nil {
		_ = c.Terminate(ctx)
		return nil, err
	}
	return s, nil
}

// createBuckets retries because the master and volume server need a moment after the S3 port opens.
func (s *Seaweed) createBuckets(ctx context.Context, names ...string) error {
	client := s.Client()
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

// Client returns an S3 client with the container's credentials, for test setup and inspection.
func (s *Seaweed) Client() *s3.Client {
	return s3.New(s3.Options{
		Region:                     "us-east-1",
		BaseEndpoint:               aws.String("http://" + s.host + ":" + s.port),
		UsePathStyle:               true,
		Credentials:                credentials.NewStaticCredentialsProvider(s.accessKey, s.secretKey, ""),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
}

// Config returns the storage configuration for the container's two buckets.
func (s *Seaweed) Config() config.S3 {
	return config.S3{
		Endpoint:        "http://" + s.host + ":" + s.port,
		PublicEndpoint:  "http://" + s.host + ":" + s.port,
		Region:          "us-east-1",
		ForcePathStyle:  true,
		SourceBucket:    SourceBucket,
		DeliveryBucket:  DeliveryBucket,
		AccessKeyID:     config.NewStaticCredential(s.accessKey),
		SecretAccessKey: config.NewStaticCredential(s.secretKey),
	}
}
