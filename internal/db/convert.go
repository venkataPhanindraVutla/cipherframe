package db

import (
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// toPG converts a typed ID to the database representation. The zero ID becomes NULL.
func toPG[K id.Kind](i id.ID[K]) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(i.UUID()), Valid: !i.IsZero()}
}

// fromPG converts a database UUID to a typed ID. NULL becomes the zero ID.
func fromPG[K id.Kind](u pgtype.UUID) id.ID[K] {
	if !u.Valid {
		return id.ID[K]{}
	}
	return id.FromUUID[K](uuid.UUID(u.Bytes))
}

// requirePG is toPG for IDs that must be present.
func requirePG[K id.Kind](i id.ID[K]) (pgtype.UUID, error) {
	if i.IsZero() {
		return pgtype.UUID{}, errs.New(errs.InvalidRequest, "a required identifier is missing")
	}
	return toPG(i), nil
}

func rawToPG(u uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(u), Valid: u != uuid.Nil()}
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func strVal(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func tenantFromRow(r dbgen.Tenant) Tenant {
	return Tenant{
		ID:         fromPG[id.TenantKind](r.ID),
		Name:       r.Name,
		CreatedAt:  r.CreatedAt.UTC(),
		DisabledAt: utcPtr(r.DisabledAt),
	}
}

func clientFromRow(r dbgen.Client) Client {
	return Client{
		ID:         fromPG[id.ClientKind](r.ID),
		TenantID:   fromPG[id.TenantKind](r.TenantID),
		Name:       r.Name,
		CreatedAt:  r.CreatedAt.UTC(),
		DisabledAt: utcPtr(r.DisabledAt),
	}
}

func scopesFromStrings(ss []string) []Scope {
	out := make([]Scope, len(ss))
	for i, s := range ss {
		out[i] = Scope(s)
	}
	return out
}

func scopesToStrings(ss []Scope) []string {
	out := make([]string, len(ss)) // non-nil: the column is NOT NULL
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}

func previousFrom(hash []byte, version *int32, until *time.Time) *PreviousSecret {
	if hash == nil || version == nil || until == nil {
		return nil
	}
	return &PreviousSecret{Hash: hash, PepperVersion: int(*version), ValidUntil: until.UTC()}
}

func apiKeyFromRow(r dbgen.ApiKey) APIKey {
	return APIKey{
		ID:            fromPG[id.APIKeyKind](r.ID),
		ClientID:      fromPG[id.ClientKind](r.ClientID),
		Name:          r.Name,
		Prefix:        r.Prefix,
		SecretHash:    r.SecretHash,
		PepperVersion: int(r.PepperVersion),
		Scopes:        scopesFromStrings(r.Scopes),
		Previous:      previousFrom(r.PreviousSecretHash, r.PreviousPepperVersion, r.PreviousValidUntil),
		CreatedAt:     r.CreatedAt.UTC(),
		RotatedAt:     utcPtr(r.RotatedAt),
		RevokedAt:     utcPtr(r.RevokedAt),
		LastUsedAt:    utcPtr(r.LastUsedAt),
	}
}

func authKeyFromRow(r dbgen.GetActiveAPIKeyByPrefixRow) AuthKey {
	return AuthKey{
		APIKey: APIKey{
			ID:            fromPG[id.APIKeyKind](r.ID),
			ClientID:      fromPG[id.ClientKind](r.ClientID),
			Name:          r.Name,
			Prefix:        r.Prefix,
			SecretHash:    r.SecretHash,
			PepperVersion: int(r.PepperVersion),
			Scopes:        scopesFromStrings(r.Scopes),
			Previous:      previousFrom(r.PreviousSecretHash, r.PreviousPepperVersion, r.PreviousValidUntil),
			CreatedAt:     r.CreatedAt.UTC(),
			RotatedAt:     utcPtr(r.RotatedAt),
			RevokedAt:     utcPtr(r.RevokedAt),
			LastUsedAt:    utcPtr(r.LastUsedAt),
		},
		TenantID:         fromPG[id.TenantKind](r.TenantID),
		ClientDisabledAt: utcPtr(r.ClientDisabledAt),
		TenantDisabledAt: utcPtr(r.TenantDisabledAt),
	}
}

func assetFromRow(r dbgen.Asset) Asset {
	a := Asset{
		ID:                  fromPG[id.AssetKind](r.ID),
		TenantID:            fromPG[id.TenantKind](r.TenantID),
		CreatedByClientID:   fromPG[id.ClientKind](r.CreatedByClientID),
		State:               AssetState(r.State),
		CreatedAt:           r.CreatedAt.UTC(),
		UpdatedAt:           r.UpdatedAt.UTC(),
		ContentType:         strVal(r.ContentType),
		UploadMethod:        UploadMethod(strVal(r.UploadMethod)),
		SourceKey:           strVal(r.SourceKey),
		S3UploadID:          strVal(r.S3UploadID),
		UploadExpiresAt:     utcPtr(r.UploadExpiresAt),
		CommittedAt:         utcPtr(r.CommittedAt),
		ProcessingStartedAt: utcPtr(r.ProcessingStartedAt),
		ReadyAt:             utcPtr(r.ReadyAt),
		FailedAt:            utcPtr(r.FailedAt),
		FailureCode:         strVal(r.FailureCode),
		SourceSHA256:        r.SourceSha256,
		Renditions:          r.Renditions,
		Progress:            int(r.Progress),
		MaskFaces:           r.MaskFaces,
		MaskingState:        strVal(r.MaskingState),
		DeletionRequestedAt: utcPtr(r.DeletionRequestedAt),
		DeletionReason:      strVal(r.DeletionReason),
		DeletedAt:           utcPtr(r.DeletedAt),
	}
	if r.FacesDetected != nil {
		n := int(*r.FacesDetected)
		a.FacesDetected = &n
	}
	if r.SizeBytes != nil {
		a.SizeBytes = *r.SizeBytes
	}
	if r.SourceSizeBytes != nil {
		a.SourceSizeBytes = *r.SourceSizeBytes
	}
	if r.DurationMs != nil {
		a.DurationMS = *r.DurationMs
	}
	return a
}

func auditFromRow(r dbgen.AuditEvent) AuditEvent {
	return AuditEvent{
		ID:        uuid.UUID(r.ID.Bytes),
		TenantID:  fromPG[id.TenantKind](r.TenantID),
		ClientID:  fromPG[id.ClientKind](r.ClientID),
		APIKeyID:  fromPG[id.APIKeyKind](r.ApiKeyID),
		Action:    r.Action,
		Target:    strVal(r.Target),
		RequestID: strVal(r.RequestID),
		CreatedAt: r.CreatedAt.UTC(),
	}
}
