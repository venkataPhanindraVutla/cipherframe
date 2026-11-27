package storage

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Buckets holds the two stores. They share clients but never a bucket.
type Buckets struct {
	// Source holds uploaded originals. Nothing served to viewers references it.
	Source Store
	// Delivery holds encrypted segments, playlists and derived artifacts.
	Delivery DeliveryStore
}

// New builds both stores from the configuration. It makes no network call.
//
// Two S3 clients are created (ADR 0014). The internal client uses cfg.Endpoint for every
// server-side call. The public client uses cfg.PublicEndpoint and only signs URLs, because a
// presigned URL's signature covers the host and a browser cannot reach an internal address.
func New(ctx context.Context, cfg config.S3) (*Buckets, error) {
	if cfg.SourceBucket == "" || cfg.DeliveryBucket == "" {
		return nil, errors.New("storage: source and delivery bucket names are required")
	}
	if cfg.SourceBucket == cfg.DeliveryBucket {
		return nil, errors.New("storage: source and delivery buckets must differ")
	}
	c, err := newClients(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Buckets{
		Source:   &s3Store{api: c.internal, pre: c.presign, bucket: cfg.SourceBucket, role: keys.Source},
		Delivery: deliveryStore{&s3Store{api: c.internal, pre: c.presign, bucket: cfg.DeliveryBucket, role: keys.Delivery}},
	}, nil
}

// NewS3Client returns the internal S3 client for server-side calls, configured exactly like the
// one behind the Stores. It is for libraries that need the raw SDK client (the tus data store in
// the edge role). Never hand it, or anything derived from it, to a client of the API.
func NewS3Client(ctx context.Context, cfg config.S3) (*s3.Client, error) {
	c, err := newClients(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return c.internal, nil
}

type clients struct {
	internal *s3.Client
	presign  *s3.PresignClient
}

func newClients(ctx context.Context, cfg config.S3) (*clients, error) {
	creds, err := credentialsFor(ctx, cfg)
	if err != nil {
		return nil, err
	}
	internal := s3.New(clientOptions(cfg, creds, cfg.Endpoint))
	public := s3.New(clientOptions(cfg, creds, publicEndpoint(cfg)))
	return &clients{internal: internal, presign: s3.NewPresignClient(public)}, nil
}

func publicEndpoint(cfg config.S3) string {
	if cfg.PublicEndpoint != "" {
		return cfg.PublicEndpoint
	}
	return cfg.Endpoint
}

// clientOptions builds SDK options. Checksums are calculated only where S3 requires them: the
// default (always) adds trailing checksums that several S3-compatible stores reject and puts a
// checksum parameter into presigned URLs that a browser then has to match.
func clientOptions(cfg config.S3, creds aws.CredentialsProvider, endpoint string) s3.Options {
	o := s3.Options{
		Region:                     cfg.Region,
		Credentials:                creds,
		UsePathStyle:               cfg.ForcePathStyle,
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	if endpoint != "" {
		o.BaseEndpoint = aws.String(endpoint)
	}
	return o
}

func credentialsFor(ctx context.Context, cfg config.S3) (aws.CredentialsProvider, error) {
	return Credentials(ctx, "storage", cfg.Region, cfg.AccessKeyID, cfg.SecretAccessKey, true)
}

// Credentials selects the credential source from the configuration state:
//
//	Static        -> the configured key pair
//	ProviderChain -> the SDK default chain (environment, shared config, instance or task role)
//	Unset         -> anonymous when anonymousIfUnset (development only; config rejects Unset in
//	                 production), otherwise the SDK default chain
//
// Mixed states are rejected, as are static states with an empty half. prefix labels errors.
func Credentials(ctx context.Context, prefix, region string, id, secret config.Credential, anonymousIfUnset bool) (aws.CredentialsProvider, error) {
	if id.State() != secret.State() {
		return nil, errors.New(prefix + ": access key ID and secret access key must be in the same state")
	}
	state := id.State()
	if state == config.Unset && anonymousIfUnset {
		return aws.AnonymousCredentials{}, nil
	}
	switch state {
	case config.Static:
		if id.Secret().IsEmpty() || secret.Secret().IsEmpty() {
			return nil, errors.New(prefix + ": static credentials must not be empty")
		}
		return credentials.NewStaticCredentialsProvider(id.Secret().Reveal(), secret.Secret().Reveal(), ""), nil
	case config.ProviderChain, config.Unset:
		// The region is passed explicitly so the shared config cannot change it.
		def, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return nil, errors.New(prefix + ": cannot load the default credential chain")
		}
		return def.Credentials, nil
	default:
		return nil, errors.New(prefix + ": unknown credential state")
	}
}
