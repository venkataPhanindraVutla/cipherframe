package db

import (
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

// Asset is the asset skeleton; later milestones add columns.
type Asset struct {
	ID                id.AssetID
	TenantID          id.TenantID
	CreatedByClientID id.ClientID
	State             AssetState
	CreatedAt         time.Time
	UpdatedAt         time.Time
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
