package api

import (
	"context"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// auditQuery converts the query parameters of the audit export.
func auditQuery(p gen.ListAuditEventsParams) (db.AuditQuery, error) {
	q := db.AuditQuery{Limit: defaultAccessLogPage}
	var fields []errs.FieldError
	bad := func(field, msg string) { fields = append(fields, errs.FieldError{Field: field, Message: msg}) }
	if p.Limit != nil {
		if *p.Limit < 1 || *p.Limit > db.MaxEventPage {
			bad("limit", "must be between 1 and 500")
		} else {
			q.Limit = *p.Limit
		}
	}
	if p.Since != nil {
		q.Since = p.Since.UTC()
	}
	if p.Until != nil {
		q.Until = p.Until.UTC()
	}
	if p.Since != nil && p.Until != nil && !q.Until.After(q.Since) {
		bad("until", "must be after since")
	}
	if p.After != nil {
		c, err := db.ParseAuditCursor(*p.After)
		if err != nil {
			bad("after", "is invalid")
		} else {
			q.After = &c
		}
	}
	if len(fields) > 0 {
		return db.AuditQuery{}, errs.Invalid("The request is invalid.", fields)
	}
	return q, nil
}

// ListAuditEvents exports the audit events of the caller's tenant, oldest first.
func (s *server) ListAuditEvents(ctx context.Context, req gen.ListAuditEventsRequestObject) (gen.ListAuditEventsResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if s.repos == nil {
		return nil, errs.New(errs.DependencyUnavailable, "The audit log is not available.")
	}
	q, err := auditQuery(req.Params)
	if err != nil {
		return nil, err
	}
	events, next, err := s.repos.ListAuditEvents(ctx, p.TenantID, q)
	if err != nil {
		return nil, err
	}
	out := gen.AuditEventList{Items: make([]gen.AuditEvent, len(events))}
	for i, e := range events {
		item := gen.AuditEvent{Id: openapi_types.UUID(e.ID), Action: e.Action, CreatedAt: e.CreatedAt}
		if !e.ClientID.IsZero() {
			c := e.ClientID.String()
			item.ClientId = &c
		}
		if !e.APIKeyID.IsZero() {
			k := e.APIKeyID.String()
			item.KeyId = &k
		}
		if e.Target != "" {
			item.Target = &e.Target
		}
		if e.RequestID != "" {
			item.RequestId = &e.RequestID
		}
		out.Items[i] = item
	}
	if next != nil {
		c := next.Encode()
		out.NextCursor = &c
	}
	return gen.ListAuditEvents200JSONResponse{
		Body: out, Headers: gen.ListAuditEvents200ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)},
	}, nil
}
