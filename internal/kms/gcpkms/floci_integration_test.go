//go:build integration

package gcpkms_test

import (
	"context"
	"net"
	"path"
	"testing"
	"time"

	kmsapi "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/gcpkms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
)

// flociGCPImage is the Floci GCP emulator (MIT), pinned by tag and digest (ADR 0035).
const flociGCPImage = "floci/floci-gcp:0.12.0@sha256:d02e70407d6b37c3e24e31b5ccf100606735cba4f84fd476708b35afd052abb3"

// TestFlociConformance runs the provider conformance suite against Cloud KMS as emulated by Floci,
// over the real gRPC protocol: a check that does not depend on the in-process fake.
func TestFlociConformance(t *testing.T) {
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        flociGCPImage,
			ExposedPorts: []string{"4588/tcp"},
			WaitingFor:   wait.ForListeningPort("4588/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if c != nil {
		t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	}
	if err != nil {
		t.Fatalf("floci-gcp setup failed: %v", err)
	}
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := c.MappedPort(ctx, "4588/tcp")
	if err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort(host, port.Port())
	dial := func(t *testing.T) option.ClientOption {
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return option.WithGRPCConn(conn)
	}

	admin, err := kmsapi.NewKeyManagementClient(ctx, dial(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	// The port opens before the service answers, so the first call retries for a while.
	var ring *kmspb.KeyRing
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		ring, err = admin.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
			Parent: "projects/cipherframe-test/locations/global", KeyRingId: "conformance",
		})
		if err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		t.Fatalf("CreateKeyRing: %v", err)
	}
	key, err := admin.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent: ring.GetName(), CryptoKeyId: "content",
		CryptoKey: &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}
	name := key.GetName()

	open := func(t *testing.T) kms.Provider {
		p, err := gcpkms.New(ctx, config.KMSGCP{KeyName: name, Timeout: 10 * time.Second}, dial(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	kmstest.Run(t, open, kmstest.WithRotated(func(t *testing.T) kms.Provider {
		v, err := admin.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{Parent: name})
		if err != nil {
			t.Fatalf("CreateCryptoKeyVersion: %v", err)
		}
		if _, err := admin.UpdateCryptoKeyPrimaryVersion(ctx, &kmspb.UpdateCryptoKeyPrimaryVersionRequest{
			Name: name, CryptoKeyVersionId: path.Base(v.GetName()),
		}); err != nil {
			t.Fatalf("UpdateCryptoKeyPrimaryVersion: %v", err)
		}
		return open(t)
	}))
}
