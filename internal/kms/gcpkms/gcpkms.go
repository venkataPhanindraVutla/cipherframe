//go:build !nokms_gcp

// Package gcpkms is the GCP Cloud KMS key provider (M2-2, ADR 0022, ADR 0023). It wraps content
// keys with Cloud KMS symmetric encryption (Encrypt and Decrypt on a crypto key), binds the
// caller's associated data as Cloud KMS additional authenticated data, and verifies the CRC32C
// checksums the API offers in both directions, as Google's data-integrity guidance asks.
//
// Cloud KMS picks the key version from the ciphertext on Decrypt, so keys wrapped before a rotation
// stay readable while new wraps use the primary version. Errors keep only a kind and a fixed
// sentence: the SDK's error text is dropped and only the gRPC status code is used to classify it.
//
// The package is excluded from a build with the nokms_gcp tag, which keeps the Cloud KMS SDK and
// its gRPC stack out of the binary.
package gcpkms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"strconv"
	"strings"
	"time"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

// Name is the provider name recorded in every wrapped key.
const Name = "gcpkms"

const versionSegment = "/cryptoKeyVersions/"

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func checksum(b []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(b, castagnoli)))
}

func matches(got *wrapperspb.Int64Value, b []byte) bool {
	return got != nil && got.GetValue() == int64(crc32.Checksum(b, castagnoli))
}

// Provider is the GCP Cloud KMS key provider. It is safe for concurrent use.
type Provider struct {
	client  *cloudkms.KeyManagementClient
	keyName string
	timeout time.Duration
}

// New builds the provider from configuration. Credentials come from cfg.CredentialsFile when set
// and from Application Default Credentials otherwise. extra options are applied last; tests use
// them to dial a fake server. It does not contact Cloud KMS.
func New(ctx context.Context, cfg config.KMSGCP, extra ...option.ClientOption) (*Provider, error) {
	if cfg.KeyName == "" {
		return nil, errors.New("gcpkms: no key name configured")
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("gcpkms: the timeout must be positive")
	}
	var opts []option.ClientOption
	if cfg.CredentialsFile != "" {
		o, err := credentialsOption(cfg.CredentialsFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, o)
	}
	if cfg.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(cfg.Endpoint))
	}
	opts = append(opts, extra...)
	c, err := cloudkms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, errors.New("gcpkms: cannot create the Cloud KMS client (check the credentials and the endpoint)")
	}
	return &Provider{client: c, keyName: cfg.KeyName, timeout: cfg.Timeout}, nil
}

// credentialsOption reads the "type" of a credentials file and selects the matching option. Error
// text is fixed: the file may hold a private key.
func credentialsOption(path string) (option.ClientOption, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, errors.New("gcpkms: cannot read the credentials file")
	}
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, errors.New("gcpkms: the credentials file is not valid JSON")
	}
	switch t := option.CredentialsType(head.Type); t {
	case option.ServiceAccount, option.AuthorizedUser, option.ExternalAccount, option.ImpersonatedServiceAccount:
		return option.WithAuthCredentialsJSON(t, b), nil
	}
	return nil, errors.New("gcpkms: the credentials file has an unsupported type")
}

// Close releases the client's connections.
func (p *Provider) Close() error { return p.client.Close() }

// Name implements kms.Provider.
func (*Provider) Name() string { return Name }

// String implements fmt.Stringer. It names the key, which is an identifier and not a secret.
func (p *Provider) String() string { return "gcpkms-provider(" + p.keyName + ")" }

func (p *Provider) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, p.timeout)
}

// Current implements kms.Provider. It returns the primary version of the configured key and
// refuses a key that is not a symmetric ENCRYPT_DECRYPT key with an enabled primary version.
func (p *Provider) Current(ctx context.Context) (kms.KeyRef, error) {
	if err := kms.FromContext(ctx, Name, "current"); err != nil {
		return kms.KeyRef{}, err
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	key, err := p.client.GetCryptoKey(cctx, &kmspb.GetCryptoKeyRequest{Name: p.keyName})
	if err != nil {
		return kms.KeyRef{}, mapError(ctx, "current", err, false)
	}
	if key.GetPurpose() != kmspb.CryptoKey_ENCRYPT_DECRYPT {
		return kms.KeyRef{}, kms.New(kms.NotConfigured, Name, "current", "the key purpose is not ENCRYPT_DECRYPT")
	}
	primary := key.GetPrimary()
	if primary == nil {
		return kms.KeyRef{}, kms.New(kms.NotConfigured, Name, "current", "the key has no primary version")
	}
	if primary.GetState() != kmspb.CryptoKeyVersion_ENABLED {
		return kms.KeyRef{}, kms.New(kms.NotConfigured, Name, "current", "the primary key version is not enabled")
	}
	v, ok := p.versionOf(primary.GetName())
	if !ok {
		return kms.KeyRef{}, kms.New(kms.Other, Name, "current", "the primary version name is malformed")
	}
	return kms.KeyRef{KeyID: p.keyName, Version: v}, nil
}

// versionOf extracts N from "<key>/cryptoKeyVersions/N" and requires the key to be ours.
func (p *Provider) versionOf(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, p.keyName+versionSegment)
	if !ok {
		return "", false
	}
	n, err := strconv.ParseUint(rest, 10, 63)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != rest {
		return "", false
	}
	return rest, true
}

// Wrap implements kms.Provider.
func (p *Provider) Wrap(ctx context.Context, plaintext, aad []byte) (kms.Wrapped, error) {
	if err := kms.FromContext(ctx, Name, "wrap"); err != nil {
		return kms.Wrapped{}, err
	}
	if len(plaintext) == 0 {
		return kms.Wrapped{}, kms.New(kms.Invalid, Name, "wrap", "plaintext is empty")
	}
	if len(aad) == 0 {
		return kms.Wrapped{}, kms.New(kms.Invalid, Name, "wrap", "associated data is empty")
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	resp, err := p.client.Encrypt(cctx, &kmspb.EncryptRequest{
		Name:                              p.keyName,
		Plaintext:                         plaintext,
		AdditionalAuthenticatedData:       aad,
		PlaintextCrc32C:                   checksum(plaintext),
		AdditionalAuthenticatedDataCrc32C: checksum(aad),
	})
	if err != nil {
		return kms.Wrapped{}, mapError(ctx, "wrap", err, false)
	}
	if !resp.GetVerifiedPlaintextCrc32C() || !resp.GetVerifiedAdditionalAuthenticatedDataCrc32C() {
		return kms.Wrapped{}, kms.New(kms.Other, Name, "wrap", "Cloud KMS did not verify the request checksums")
	}
	ct := resp.GetCiphertext()
	if len(ct) == 0 || !matches(resp.GetCiphertextCrc32C(), ct) {
		return kms.Wrapped{}, kms.New(kms.Other, Name, "wrap", "the ciphertext checksum does not match")
	}
	v, ok := p.versionOf(resp.GetName())
	if !ok {
		return kms.Wrapped{}, kms.New(kms.Other, Name, "wrap", "the response names an unexpected key version")
	}
	return kms.Wrapped{Provider: Name, KeyID: p.keyName, Version: v, Ciphertext: ct}, nil
}

// Unwrap implements kms.Provider. It never returns partial plaintext: on any failure the result is
// nil.
func (p *Provider) Unwrap(ctx context.Context, w kms.Wrapped, aad []byte) ([]byte, error) {
	if err := kms.FromContext(ctx, Name, "unwrap"); err != nil {
		return nil, err
	}
	if w.Provider != Name {
		return nil, kms.New(kms.Invalid, Name, "unwrap", "the key was not wrapped by this provider")
	}
	if w.KeyID != p.keyName {
		return nil, kms.New(kms.NotConfigured, Name, "unwrap", "the key was wrapped under a different Cloud KMS key")
	}
	if len(aad) == 0 {
		return nil, kms.New(kms.Invalid, Name, "unwrap", "associated data is empty")
	}
	if len(w.Ciphertext) == 0 {
		return nil, kms.New(kms.Invalid, Name, "unwrap", "malformed wrapped key")
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	resp, err := p.client.Decrypt(cctx, &kmspb.DecryptRequest{
		Name:                              p.keyName,
		Ciphertext:                        w.Ciphertext,
		AdditionalAuthenticatedData:       aad,
		CiphertextCrc32C:                  checksum(w.Ciphertext),
		AdditionalAuthenticatedDataCrc32C: checksum(aad),
	})
	if err != nil {
		return nil, mapError(ctx, "unwrap", err, true)
	}
	pt := resp.GetPlaintext()
	if len(pt) == 0 || !matches(resp.GetPlaintextCrc32C(), pt) {
		clear(pt)
		return nil, kms.New(kms.Other, Name, "unwrap", "the plaintext checksum does not match")
	}
	return pt, nil
}

// mapError classifies an SDK error by gRPC status code only, and keeps none of its text.
func mapError(ctx context.Context, op string, err error, decrypt bool) error {
	if e := kms.FromContext(ctx, Name, op); e != nil {
		return e
	}
	// The per-request timeout expired, possibly while the SDK was still retrying: the SDK then
	// returns the context error rather than a status.
	if errors.Is(err, context.DeadlineExceeded) {
		return kms.New(kms.Unavailable, Name, op, "Cloud KMS is unavailable or timed out")
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Internal:
		return kms.New(kms.Unavailable, Name, op, "Cloud KMS is unavailable or timed out")
	case codes.PermissionDenied, codes.Unauthenticated:
		return kms.New(kms.Denied, Name, op, "Cloud KMS refused the credentials or the operation")
	case codes.InvalidArgument:
		if decrypt {
			return kms.New(kms.Invalid, Name, op, "authentication failed")
		}
	case codes.NotFound, codes.FailedPrecondition:
		return kms.New(kms.NotConfigured, Name, op, "the key or key version is missing, disabled or destroyed")
	}
	return kms.New(kms.Other, Name, op, "Cloud KMS returned an unexpected error")
}

var _ kms.Provider = (*Provider)(nil)

var _ fmt.Stringer = (*Provider)(nil)
