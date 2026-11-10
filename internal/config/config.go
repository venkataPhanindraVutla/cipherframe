package config

import (
	"log/slog"
	"strconv"
	"strings"
)

// Environment variable names.
const (
	EnvEnv                 = "CIPHERFRAME_ENV"
	EnvLogLevel            = "CIPHERFRAME_LOG_LEVEL"
	EnvAPIListen           = "CIPHERFRAME_API_LISTEN"
	EnvEdgeListen          = "CIPHERFRAME_EDGE_LISTEN"
	EnvDatabaseURL         = "CIPHERFRAME_DATABASE_URL"
	EnvS3Endpoint          = "CIPHERFRAME_S3_ENDPOINT"
	EnvS3PublicEndpoint    = "CIPHERFRAME_S3_PUBLIC_ENDPOINT"
	EnvS3Region            = "CIPHERFRAME_S3_REGION"
	EnvS3ForcePathStyle    = "CIPHERFRAME_S3_FORCE_PATH_STYLE"
	EnvS3SourceBucket      = "CIPHERFRAME_S3_SOURCE_BUCKET"
	EnvS3DeliveryBucket    = "CIPHERFRAME_S3_DELIVERY_BUCKET"
	EnvS3AccessKeyID       = "CIPHERFRAME_S3_ACCESS_KEY_ID"
	EnvS3SecretAccessKey   = "CIPHERFRAME_S3_SECRET_ACCESS_KEY"
	EnvAPIKeyPeppers       = "CIPHERFRAME_API_KEY_PEPPERS"
	EnvAPIKeyPepperCurrent = "CIPHERFRAME_API_KEY_PEPPER_CURRENT"
)

// PlaceholderPrefix marks a development placeholder secret. Production
// refuses to start with any secret that carries it.
const PlaceholderPrefix = "dev-placeholder-"

// Environment is the deployment mode.
type Environment string

// Deployment modes.
const (
	Development Environment = "development"
	Production  Environment = "production"
)

// S3 is the object-storage configuration.
type S3 struct {
	// Endpoint is empty when the provider default is used.
	Endpoint string
	// PublicEndpoint is the endpoint browsers use; it defaults to Endpoint.
	PublicEndpoint  string
	Region          string
	ForcePathStyle  bool
	SourceBucket    string
	DeliveryBucket  string
	AccessKeyID     Credential
	SecretAccessKey Credential
}

// Config is the validated configuration. Secret-bearing fields use types that
// never print their value. Fields are exported so fmt can reach their
// formatters.
type Config struct {
	Env         Environment
	LogLevel    slog.Level
	APIListen   string
	EdgeListen  string
	DatabaseURL Secret
	S3          S3
	Peppers     Peppers
}

// LogValue implements slog.LogValuer. It shows the effective configuration
// with secrets redacted and credentials reduced to their state.
func (c *Config) LogValue() slog.Value {
	if c == nil {
		return slog.StringValue("<nil>")
	}
	versions := c.Peppers.Versions()
	vs := make([]string, len(versions))
	for i, v := range versions {
		vs[i] = strconv.Itoa(v)
	}
	return slog.GroupValue(
		slog.String("env", string(c.Env)),
		slog.String("log_level", c.LogLevel.String()),
		slog.String("api_listen", c.APIListen),
		slog.String("edge_listen", c.EdgeListen),
		slog.Any("database_url", c.DatabaseURL),
		slog.Group("s3",
			slog.String("endpoint", c.S3.Endpoint),
			slog.String("public_endpoint", c.S3.PublicEndpoint),
			slog.String("region", c.S3.Region),
			slog.Bool("force_path_style", c.S3.ForcePathStyle),
			slog.String("source_bucket", c.S3.SourceBucket),
			slog.String("delivery_bucket", c.S3.DeliveryBucket),
			slog.Any("access_key_id", c.S3.AccessKeyID),
			slog.Any("secret_access_key", c.S3.SecretAccessKey),
		),
		slog.Group("api_key_peppers",
			slog.String("versions", strings.Join(vs, ",")),
			slog.Int("current", c.Peppers.current),
			slog.String("values", Redacted),
		),
	)
}
