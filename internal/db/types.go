package db

import (
	"fmt"
	"io"
	"log/slog"
	"time"
	"uuid"

	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// Scope is an API key scope (ADR 0009). Scope names are public API.
type Scope string

// The allowed scopes. The database enforces the same set with a CHECK constraint.
const (
	ScopeAssetsRead     Scope = "assets:read"
	ScopeAssetsWrite    Scope = "assets:write"
	ScopeSessionsWrite  Scope = "sessions:write"
	ScopeWebhooksManage Scope = "webhooks:manage"
	ScopeAdmin          Scope = "admin"
)

// Valid reports whether s is an allowed scope.
func (s Scope) Valid() bool {
	switch s {
	case ScopeAssetsRead, ScopeAssetsWrite, ScopeSessionsWrite, ScopeWebhooksManage, ScopeAdmin:
		return true
	}
	return false
}

// AssetState is the lifecycle state of an asset.
type AssetState string

// Asset lifecycle states.
const (
	AssetCreated    AssetState = "created"
	AssetUploading  AssetState = "uploading"
	AssetCommitted  AssetState = "committed"
	AssetProcessing AssetState = "processing"
	AssetReady      AssetState = "ready"
	AssetFailed     AssetState = "failed"
	AssetDeleted    AssetState = "deleted"
)

// Valid reports whether s is an allowed state.
func (s AssetState) Valid() bool {
	switch s {
	case AssetCreated, AssetUploading, AssetCommitted, AssetProcessing, AssetReady, AssetFailed, AssetDeleted:
		return true
	}
	return false
}

// Tenant is the isolation boundary.
type Tenant struct {
	ID         id.TenantID
	Name       string
	CreatedAt  time.Time
	DisabledAt *time.Time
}

// Client is one embedding application or environment inside a tenant.
type Client struct {
	ID         id.ClientID
	TenantID   id.TenantID
	Name       string
	CreatedAt  time.Time
	DisabledAt *time.Time
}

// PreviousSecret is the secret a rotated key accepted before rotation, valid until ValidUntil.
type PreviousSecret struct {
	Hash          []byte
	PepperVersion int
	ValidUntil    time.Time
}

// APIKey is a named, scoped credential belonging to a client. SecretHash is
// HMAC-SHA256(pepper, secret); the secret itself is never stored. Never log a key row.
type APIKey struct {
	ID            id.APIKeyID
	ClientID      id.ClientID
	Name          string
	Prefix        string
	SecretHash    []byte
	PepperVersion int
	Scopes        []Scope
	Previous      *PreviousSecret // nil when the key has never been rotated
	CreatedAt     time.Time
	RotatedAt     *time.Time
	RevokedAt     *time.Time
	LastUsedAt    *time.Time
}

// AuthKey is what authentication needs: the key plus the tenant that owns it and the disabled
// markers of its client and tenant, so the caller can fail closed.
type AuthKey struct {
	APIKey
	TenantID         id.TenantID
	ClientDisabledAt *time.Time
	TenantDisabledAt *time.Time
}

// UploadMethod is how an asset's source is uploaded (ADR 0025).
type UploadMethod string

// Upload methods.
const (
	UploadTus       UploadMethod = "tus"
	UploadMultipart UploadMethod = "multipart"
)

// Valid reports whether m is an allowed method.
func (m UploadMethod) Valid() bool { return m == UploadTus || m == UploadMultipart }

// Asset is a video asset and its lifecycle (assetfsm.go). Nullable columns are the zero value
// (or nil for times) when unset.
//
// SourceKey is the object key of the upload in the source bucket and S3UploadID the object
// store's multipart upload ID. Neither may ever leave the process: the API converts an Asset
// field by field, and Asset prints without them in every formatting verb and in logs.
type Asset struct {
	ID                  id.AssetID
	TenantID            id.TenantID
	CreatedByClientID   id.ClientID
	State               AssetState
	CreatedAt           time.Time
	UpdatedAt           time.Time
	SizeBytes           int64
	ContentType         string
	UploadMethod        UploadMethod
	SourceKey           string
	S3UploadID          string
	UploadExpiresAt     *time.Time
	CommittedAt         *time.Time
	ProcessingStartedAt *time.Time
	ReadyAt             *time.Time
	FailedAt            *time.Time
	FailureCode         string
	// SourceSHA256 and SourceSizeBytes are measured by the worker while it streams the source
	// (nil and 0 until then). DurationMS and Renditions (a JSON summary) are set when the asset
	// becomes ready. Progress is a 0-100 hint while processing.
	SourceSHA256    []byte
	SourceSizeBytes int64
	DurationMS      int64
	Renditions      []byte
	Progress        int
}

// String implements fmt.Stringer without the source key or upload ID.
func (a Asset) String() string { return "asset " + a.ID.String() + " (" + string(a.State) + ")" }

// GoString implements fmt.GoStringer.
func (a Asset) GoString() string { return a.String() }

// Format implements fmt.Formatter and covers every verb, so %+v and %#v cannot print the key.
func (a Asset) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

// LogValue implements slog.LogValuer.
func (a Asset) LogValue() slog.Value { return slog.StringValue(a.String()) }

// UploadPart is one part of a multipart upload that edge stored (ADR 0025).
type UploadPart struct {
	PartNumber int
	ETag       string
	SizeBytes  int64
	CreatedAt  time.Time
}

// UploadGrant is what the edge learns from a valid upload token: the asset it is bound to and
// when the token expires. The caller must still check the expiry and the asset's state.
type UploadGrant struct {
	Asset          Asset
	TokenExpiresAt time.Time
}

// AuditEvent is an append-only record. It holds no foreign keys, so it survives deletion of what
// it describes. ID is a UUIDv7 (audit events have no public ID prefix). ClientID and APIKeyID are
// the zero value when not applicable.
type AuditEvent struct {
	ID        uuid.UUID
	TenantID  id.TenantID
	ClientID  id.ClientID
	APIKeyID  id.APIKeyID
	Action    string
	Target    string
	RequestID string
	CreatedAt time.Time
}

// NewAPIKey is the input for CreateAPIKey. The caller generates the prefix and hashes the secret.
type NewAPIKey struct {
	ClientID      id.ClientID
	Name          string
	Prefix        string
	SecretHash    []byte
	PepperVersion int
	Scopes        []Scope
}

// RotateParams is the input for RotateAPIKey. PreviousValidUntil may equal RotatedAt (no overlap).
type RotateParams struct {
	NewSecretHash      []byte
	NewPepperVersion   int
	RotatedAt          time.Time
	PreviousValidUntil time.Time
}

// NewAuditEvent is the input for InsertAuditEvent. Empty strings and zero IDs are stored as NULL.
type NewAuditEvent struct {
	TenantID  id.TenantID
	ClientID  id.ClientID
	APIKeyID  id.APIKeyID
	Action    string
	Target    string
	RequestID string
}

// AuditCursor is the position after which ListAuditEvents continues: the CreatedAt and ID of the
// last event already seen.
type AuditCursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}
