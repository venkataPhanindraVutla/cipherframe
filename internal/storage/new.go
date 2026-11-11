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

// NewStore builds a single Store on bucket, for example to run the conformance suite against a real
// provider with one bucket. role only labels errors. The bucket name comes from the argument; cfg's
// bucket names are ignored. With role keys.Delivery the returned value also implements
// GetPresigner; with any other role it does not (I4).
func NewStore(ctx context.Context, cfg config.S3, bucket string, role keys.Bucket) (Store, error) {
	if bucket == "" {
		return nil, errors.New("storage: bucket name is required")
	}
	c, err := newClients(ctx, cfg)
	if err != nil {
		return nil, err
	}
	st := &s3Store{api: c.internal, pre: c.presign, bucket: bucket, role: role}
	if role == keys.Delivery {
		return deliveryStore{st}, nil
	}
	return st, nil
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

// credentialsFor selects the credential source from the configuration state:
//
//	Static        -> the configured key pair
//	ProviderChain -> the SDK default chain (environment, shared config, instance role)
//	Unset         -> anonymous (development only; config rejects Unset in production)
//
// Mixed states are rejected, as are static states with an empty half.
func credentialsFor(ctx context.Context, cfg config.S3) (aws.CredentialsProvider, error) {
	id, secret := cfg.AccessKeyID, cfg.SecretAccessKey
	if id.State() != secret.State() {
		return nil, errors.New("storage: access key ID and secret access key must be in the same state")
	}
	switch id.State() {
	case config.Static:
		if id.Secret().IsEmpty() || secret.Secret().IsEmpty() {
			return nil, errors.New("storage: static credentials must not be empty")
		}
		return credentials.NewStaticCredentialsProvider(id.Secret().Reveal(), secret.Secret().Reveal(), ""), nil
	case config.ProviderChain:
		// The region is passed explicitly so the shared config cannot change it.
		def, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
		if err != nil {
			return nil, errors.New("storage: cannot load the default credential chain")
		}
		return def.Credentials, nil
	case config.Unset:
		return aws.AnonymousCredentials{}, nil
	default:
		return nil, errors.New("storage: unknown credential state")
	}
}
