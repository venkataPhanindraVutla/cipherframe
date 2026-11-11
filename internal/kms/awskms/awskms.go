//go:build !nokms_aws

// Package awskms is the AWS KMS key provider (M2-2, ADR 0019, ADR 0022). It wraps content keys with
// the KMS Encrypt and Decrypt operations under one symmetric KMS key named in configuration, so the
// KEK never leaves KMS.
//
// Key identity and versions. Current resolves the configured key (an ARN, an alias ARN or an alias)
// with DescribeKey to the key's ARN, and every Wrapped records that ARN as KeyID. AWS rotates the
// backing key material transparently and keeps the old material for decryption, so there is no
// version a caller can see or choose: Version is the fixed value Version for every key. Repointing
// an alias at another key changes the ARN, so keys wrapped under the old key keep naming it and
// Unwrap pins that ARN; the old key must stay enabled until nothing refers to it.
//
// Associated data. KMS has no separate associated-data input, so Wrap and Unwrap send the data as
// the encryption context, base64-encoded under one fixed context key. KMS authenticates the context
// and fails Decrypt when it differs.
//
// Errors carry the AWS error code and HTTP status only. The SDK's own error text is dropped because
// it can include key ARNs and request details.
package awskms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awskmssdk "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

const (
	// Name is the provider name recorded in every wrapped key.
	Name = "awskms"
	// Version is the KEK version recorded in every wrapped key. AWS KMS exposes no caller-visible
	// version (see the package comment), so it is a constant. It is part of the associated data of
	// stored keys: never change it.
	Version = "managed"
	// ContextKey is the encryption-context key that carries the base64 associated data.
	ContextKey = "cf-aad"

	// maxPlaintext is the KMS Encrypt limit.
	maxPlaintext = 4096
)

// api is the part of the SDK client the provider uses. Unit tests inject a fake.
type api interface {
	DescribeKey(ctx context.Context, in *awskmssdk.DescribeKeyInput, opts ...func(*awskmssdk.Options)) (*awskmssdk.DescribeKeyOutput, error)
	Encrypt(ctx context.Context, in *awskmssdk.EncryptInput, opts ...func(*awskmssdk.Options)) (*awskmssdk.EncryptOutput, error)
	Decrypt(ctx context.Context, in *awskmssdk.DecryptInput, opts ...func(*awskmssdk.Options)) (*awskmssdk.DecryptOutput, error)
}

// Provider is the AWS KMS key provider. It is safe for concurrent use and holds no secret of its
// own; every printed form is a fixed string.
type Provider struct {
	api     api
	keyID   string
	timeout time.Duration
}

var _ kms.Provider = (*Provider)(nil)

// New builds the provider from configuration. It makes no network call: a key that is missing or
// disabled shows up on the first Current, Wrap or Unwrap.
func New(ctx context.Context, cfg config.KMSAWS, log *slog.Logger) (*Provider, error) {
	if cfg.KeyID == "" || cfg.Region == "" {
		return nil, errors.New("awskms: key id and region are required")
	}
	creds, err := credentialsFor(ctx, cfg)
	if err != nil {
		return nil, err
	}
	o := awskmssdk.Options{Region: cfg.Region, Credentials: creds}
	if cfg.Endpoint != "" {
		o.BaseEndpoint = aws.String(cfg.Endpoint)
	}
	if log != nil {
		log.Info("aws kms key provider configured",
			slog.String("region", cfg.Region),
			slog.String("endpoint", cfg.Endpoint),
			slog.Any("access_key_id", cfg.AccessKeyID),
			slog.Any("secret_access_key", cfg.SecretAccessKey))
	}
	return newProvider(awskmssdk.New(o), cfg.KeyID, cfg.Timeout), nil
}

func newProvider(a api, keyID string, timeout time.Duration) *Provider {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Provider{api: a, keyID: keyID, timeout: timeout}
}

// credentialsFor selects the credential source from the configuration state, as the S3 adapter does:
//
//	Static        -> the configured key pair
//	ProviderChain -> the SDK default chain (environment, shared config, instance or task role)
//	Unset         -> the SDK default chain as well: KMS has no anonymous access, so an unsigned
//	                 client could never succeed. config rejects Unset in production anyway.
//
// Mixed states are rejected, as are static states with an empty half.
func credentialsFor(ctx context.Context, cfg config.KMSAWS) (aws.CredentialsProvider, error) {
	id, secret := cfg.AccessKeyID, cfg.SecretAccessKey
	if id.State() != secret.State() {
		return nil, errors.New("awskms: access key ID and secret access key must be in the same state")
	}
	switch id.State() {
	case config.Static:
		if id.Secret().IsEmpty() || secret.Secret().IsEmpty() {
			return nil, errors.New("awskms: static credentials must not be empty")
		}
		return credentials.NewStaticCredentialsProvider(id.Secret().Reveal(), secret.Secret().Reveal(), ""), nil
	case config.ProviderChain, config.Unset:
		// The region is passed explicitly so the shared config cannot change it.
		def, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
		if err != nil {
			return nil, errors.New("awskms: cannot load the default credential chain")
		}
		return def.Credentials, nil
	default:
		return nil, errors.New("awskms: unknown credential state")
	}
}

// Name returns "awskms".
func (*Provider) Name() string { return Name }

// String, GoString and Format print a fixed string, so a provider is safe to log.
func (*Provider) String() string   { return "awskms.Provider" }
func (*Provider) GoString() string { return "awskms.Provider" }

// Format implements fmt.Formatter.
func (*Provider) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("awskms.Provider")) }

func encryptionContext(aad []byte) map[string]string {
	return map[string]string{ContextKey: base64.StdEncoding.EncodeToString(aad)}
}

// Current resolves the configured key to its ARN with DescribeKey. The key must be an enabled
// symmetric encryption key; any other state is NotConfigured, so a wrap is never attempted under a
// key that cannot decrypt.
func (p *Provider) Current(ctx context.Context) (kms.KeyRef, error) {
	const op = "current"
	if ce := kms.FromContext(ctx, Name, op); ce != nil {
		return kms.KeyRef{}, ce
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	out, err := p.api.DescribeKey(ctx, &awskmssdk.DescribeKeyInput{KeyId: aws.String(p.keyID)})
	if err != nil {
		return kms.KeyRef{}, fail(ctx, op, err)
	}
	m := out.KeyMetadata
	arn := ""
	if m != nil {
		arn = aws.ToString(m.Arn)
	}
	if arn == "" {
		return kms.KeyRef{}, kms.New(kms.Other, Name, op, "the response named no key")
	}
	if m.KeyState != "" && m.KeyState != kmstypes.KeyStateEnabled {
		return kms.KeyRef{}, kms.New(kms.NotConfigured, Name, op, "the key is not enabled")
	}
	if (m.KeyUsage != "" && m.KeyUsage != kmstypes.KeyUsageTypeEncryptDecrypt) ||
		(m.KeySpec != "" && m.KeySpec != kmstypes.KeySpecSymmetricDefault) {
		return kms.KeyRef{}, kms.New(kms.NotConfigured, Name, op, "the key is not a symmetric encryption key")
	}
	return kms.KeyRef{KeyID: arn, Version: Version}, nil
}

// Wrap encrypts plaintext (at most 4096 bytes, the KMS limit) under the configured key, binding aad
// as the encryption context. The result records the key ARN KMS reports.
func (p *Provider) Wrap(ctx context.Context, plaintext, aad []byte) (kms.Wrapped, error) {
	const op = "wrap"
	switch {
	case len(plaintext) == 0:
		return kms.Wrapped{}, kms.New(kms.Invalid, Name, op, "plaintext is empty")
	case len(plaintext) > maxPlaintext:
		return kms.Wrapped{}, kms.New(kms.Invalid, Name, op, "plaintext is longer than 4096 bytes")
	case len(aad) == 0:
		return kms.Wrapped{}, kms.New(kms.Invalid, Name, op, "associated data is empty")
	}
	if ce := kms.FromContext(ctx, Name, op); ce != nil {
		return kms.Wrapped{}, ce
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	out, err := p.api.Encrypt(ctx, &awskmssdk.EncryptInput{
		KeyId:               aws.String(p.keyID),
		Plaintext:           plaintext,
		EncryptionContext:   encryptionContext(aad),
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return kms.Wrapped{}, fail(ctx, op, err)
	}
	arn := aws.ToString(out.KeyId)
	if arn == "" || len(out.CiphertextBlob) == 0 {
		return kms.Wrapped{}, kms.New(kms.Other, Name, op, "the response was incomplete")
	}
	return kms.Wrapped{Provider: Name, KeyID: arn, Version: Version, Ciphertext: out.CiphertextBlob}, nil
}

// Unwrap decrypts w with the same encryption context as Wrap, pinning KMS to the key ARN stored in
// w so a ciphertext cannot be opened by another key. A key that decrypts under a different ARN than
// the stored one is rejected.
func (p *Provider) Unwrap(ctx context.Context, w kms.Wrapped, aad []byte) ([]byte, error) {
	const op = "unwrap"
	switch {
	case w.Provider != Name:
		return nil, kms.New(kms.NotConfigured, Name, op, "the wrapped key was made by another provider")
	case len(aad) == 0:
		return nil, kms.New(kms.Invalid, Name, op, "associated data is empty")
	case len(w.Ciphertext) == 0:
		return nil, kms.New(kms.Invalid, Name, op, "ciphertext is empty")
	case w.KeyID == "":
		return nil, kms.New(kms.Invalid, Name, op, "the wrapped key names no KMS key")
	case w.Version != Version:
		return nil, kms.New(kms.NotConfigured, Name, op, "the wrapped key names an unknown version")
	}
	if ce := kms.FromContext(ctx, Name, op); ce != nil {
		return nil, ce
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	out, err := p.api.Decrypt(ctx, &awskmssdk.DecryptInput{
		KeyId:               aws.String(w.KeyID),
		CiphertextBlob:      w.Ciphertext,
		EncryptionContext:   encryptionContext(aad),
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return nil, fail(ctx, op, err)
	}
	if got := aws.ToString(out.KeyId); got != "" && got != w.KeyID {
		return nil, kms.New(kms.Invalid, Name, op, "the key that decrypted is not the key that wrapped")
	}
	if len(out.Plaintext) == 0 {
		return nil, kms.New(kms.Other, Name, op, "the response was incomplete")
	}
	return out.Plaintext, nil
}
