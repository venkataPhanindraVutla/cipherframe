//go:build !nokms_gcp

package gcpkms_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"sync"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const testKey = "projects/p/locations/global/keyRings/r/cryptoKeys/k"

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func crc(b []byte) int64 { return int64(crc32.Checksum(b, castagnoli)) }

// fakeKMS is an in-process Cloud KMS: real AES-256-GCM per key version, a primary version that can
// be rotated, the CRC32C fields of the API, and error injection. A ciphertext is the 4-byte version,
// a 12-byte nonce and the sealed bytes, so Decrypt picks the version from the ciphertext as Cloud
// KMS does.
type fakeKMS struct {
	kmspb.UnimplementedKeyManagementServiceServer

	mu       sync.Mutex
	versions map[uint32]cipher.AEAD
	state    map[uint32]kmspb.CryptoKeyVersion_CryptoKeyVersionState
	primary  uint32
	purpose  kmspb.CryptoKey_CryptoKeyPurpose

	// Injection.
	failWith       map[string]codes.Code // method -> code
	corruptCT      bool                  // wrong ciphertext_crc32c in Encrypt responses
	corruptPT      bool                  // wrong plaintext_crc32c in Decrypt responses
	skipVerified   bool                  // verified_* false in Encrypt responses
	wrongVersion   string                // override the version name in Encrypt responses
	calls          map[string]int
	lastEncryptAAD []byte
}

func newFake() *fakeKMS {
	f := &fakeKMS{
		versions: map[uint32]cipher.AEAD{},
		state:    map[uint32]kmspb.CryptoKeyVersion_CryptoKeyVersionState{},
		purpose:  kmspb.CryptoKey_ENCRYPT_DECRYPT,
		failWith: map[string]codes.Code{},
		calls:    map[string]int{},
	}
	f.addVersion()
	return f
}

// addVersion creates the next version and makes it primary.
func (f *fakeKMS) addVersion() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := uint32(len(f.versions)) + 1 //nolint:gosec // a handful of test versions
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	f.versions[n] = g
	f.state[n] = kmspb.CryptoKeyVersion_ENABLED
	f.primary = n
	return n
}

func (f *fakeKMS) set(fn func(*fakeKMS)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeKMS) enter(method, name string) error {
	f.calls[method]++
	if c, ok := f.failWith[method]; ok {
		return status.Error(c, "injected failure: secret-looking-sdk-text")
	}
	if name != testKey {
		return status.Error(codes.NotFound, "no such key")
	}
	return nil
}

func (f *fakeKMS) GetCryptoKey(_ context.Context, r *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("GetCryptoKey", r.GetName()); err != nil {
		return nil, err
	}
	key := &kmspb.CryptoKey{Name: testKey, Purpose: f.purpose}
	if f.primary != 0 {
		key.Primary = &kmspb.CryptoKeyVersion{
			Name:  fmt.Sprintf("%s/cryptoKeyVersions/%d", testKey, f.primary),
			State: f.state[f.primary],
		}
	}
	return key, nil
}

func (f *fakeKMS) Encrypt(_ context.Context, r *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("Encrypt", r.GetName()); err != nil {
		return nil, err
	}
	if f.purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT {
		return nil, status.Error(codes.InvalidArgument, "wrong purpose")
	}
	if len(r.GetPlaintext()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "empty plaintext")
	}
	if c := r.GetPlaintextCrc32C(); c != nil && c.GetValue() != crc(r.GetPlaintext()) {
		return nil, status.Error(codes.InvalidArgument, "plaintext checksum mismatch")
	}
	if c := r.GetAdditionalAuthenticatedDataCrc32C(); c != nil && c.GetValue() != crc(r.GetAdditionalAuthenticatedData()) {
		return nil, status.Error(codes.InvalidArgument, "aad checksum mismatch")
	}
	f.lastEncryptAAD = bytes.Clone(r.GetAdditionalAuthenticatedData())
	if f.state[f.primary] != kmspb.CryptoKeyVersion_ENABLED {
		return nil, status.Error(codes.FailedPrecondition, "primary not enabled")
	}
	aead := f.versions[f.primary]
	out := binary.BigEndian.AppendUint32(nil, f.primary)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, status.Error(codes.Internal, "rand")
	}
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, r.GetPlaintext(), r.GetAdditionalAuthenticatedData())

	ctCRC := crc(out)
	if f.corruptCT {
		ctCRC++
	}
	name := fmt.Sprintf("%s/cryptoKeyVersions/%d", testKey, f.primary)
	if f.wrongVersion != "" {
		name = f.wrongVersion
	}
	return &kmspb.EncryptResponse{
		Name:                    name,
		Ciphertext:              out,
		CiphertextCrc32C:        wrapperspb.Int64(ctCRC),
		VerifiedPlaintextCrc32C: !f.skipVerified,
		VerifiedAdditionalAuthenticatedDataCrc32C: !f.skipVerified,
	}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, r *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("Decrypt", r.GetName()); err != nil {
		return nil, err
	}
	ct := r.GetCiphertext()
	if c := r.GetCiphertextCrc32C(); c != nil && c.GetValue() != crc(ct) {
		return nil, status.Error(codes.InvalidArgument, "ciphertext checksum mismatch")
	}
	if c := r.GetAdditionalAuthenticatedDataCrc32C(); c != nil && c.GetValue() != crc(r.GetAdditionalAuthenticatedData()) {
		return nil, status.Error(codes.InvalidArgument, "aad checksum mismatch")
	}
	if len(ct) < 4 {
		return nil, status.Error(codes.InvalidArgument, "decryption failed")
	}
	v := binary.BigEndian.Uint32(ct)
	aead, ok := f.versions[v]
	if !ok || len(ct) < 4+aead.NonceSize()+aead.Overhead() {
		return nil, status.Error(codes.InvalidArgument, "decryption failed")
	}
	if f.state[v] != kmspb.CryptoKeyVersion_ENABLED {
		return nil, status.Error(codes.FailedPrecondition, "key version is not enabled")
	}
	body := ct[4:]
	pt, err := aead.Open(nil, body[:aead.NonceSize()], body[aead.NonceSize():], r.GetAdditionalAuthenticatedData())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "decryption failed")
	}
	c := crc(pt)
	if f.corruptPT {
		c++
	}
	return &kmspb.DecryptResponse{Plaintext: pt, PlaintextCrc32C: wrapperspb.Int64(c)}, nil
}

// start serves f on a bufconn listener and returns a dial option source plus a stop function.
func start(t *testing.T, f *fakeKMS) (conn *grpc.ClientConn, stop func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop = func() { once.Do(func() { srv.Stop(); _ = lis.Close() }) }
	t.Cleanup(func() { stop(); _ = conn.Close() })
	return conn, stop
}
