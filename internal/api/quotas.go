package api

import (
	"context"
	"math"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/quota"
)

func (s *server) quotaService() (*quota.Service, error) {
	if s.quota == nil {
		return nil, errs.New(errs.DependencyUnavailable, "Quotas are not available.")
	}
	return s.quota, nil
}

// quotasIn validates a PUT body: every present limit is at least 1 (and the int32 columns fit).
func quotasIn(b *gen.QuotasInput) (db.Quotas, error) {
	var bad []errs.FieldError
	check := func(name string, v *int) {
		if v != nil && (*v < 1 || *v > math.MaxInt32) {
			bad = append(bad, errs.FieldError{Field: name, Message: "must be between 1 and 2147483647"})
		}
	}
	check(quota.LimitTranscodeMinutes, b.TranscodeMinutesPerMonth)
	check(quota.LimitConcurrentSessions, b.ConcurrentSessions)
	check(quota.LimitRequestsPerMinute, b.RequestsPerMinute)
	if b.StorageBytes != nil && *b.StorageBytes < 1 {
		bad = append(bad, errs.FieldError{Field: quota.LimitStorageBytes, Message: "must be at least 1"})
	}
	if len(bad) > 0 {
		return db.Quotas{}, errs.Invalid("The quotas are invalid.", bad)
	}
	return db.Quotas{
		StorageBytes: b.StorageBytes, TranscodeMinutesPerMonth: b.TranscodeMinutesPerMonth,
		ConcurrentSessions: b.ConcurrentSessions, RequestsPerMinute: b.RequestsPerMinute,
	}, nil
}

func quotasOut(q db.Quotas) gen.Quotas {
	out := gen.Quotas{
		StorageBytes: q.StorageBytes, TranscodeMinutesPerMonth: q.TranscodeMinutesPerMonth,
		ConcurrentSessions: q.ConcurrentSessions, RequestsPerMinute: q.RequestsPerMinute,
	}
	if !q.UpdatedAt.IsZero() {
		t := q.UpdatedAt
		out.UpdatedAt = &t
	}
	return out
}

func clientQuotasOut(c id.ClientID, q db.Quotas) gen.ClientQuotas {
	o := quotasOut(q)
	return gen.ClientQuotas{
		ClientId: c.String(), StorageBytes: o.StorageBytes, TranscodeMinutesPerMonth: o.TranscodeMinutesPerMonth,
		ConcurrentSessions: o.ConcurrentSessions, RequestsPerMinute: o.RequestsPerMinute, UpdatedAt: o.UpdatedAt,
	}
}

// parseClient reads a client ID from a path or query. Anything that is not one is "no such client",
// like a client of another tenant.
func parseClient(s string) (id.ClientID, error) {
	c, err := id.Parse[id.ClientKind](s)
	if err != nil {
		return id.ClientID{}, errs.New(errs.NotFound, "No such client.")
	}
	return c, nil
}

// GetQuotas returns the caller's tenant's limits.
func (s *server) GetQuotas(ctx context.Context, _ gen.GetQuotasRequestObject) (gen.GetQuotasResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.quotaService()
	if err != nil {
		return nil, err
	}
	q, err := svc.Get(ctx, p.TenantID, id.ClientID{})
	if err != nil {
		return nil, err
	}
	return gen.GetQuotas200JSONResponse{Body: quotasOut(q), Headers: gen.GetQuotas200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// UpdateQuotas replaces the caller's tenant's limits.
func (s *server) UpdateQuotas(ctx context.Context, req gen.UpdateQuotasRequestObject) (gen.UpdateQuotasResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.quotaService()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	in, err := quotasIn(req.Body)
	if err != nil {
		return nil, err
	}
	q, err := svc.Put(ctx, p.TenantID, id.ClientID{}, actor, in)
	if err != nil {
		return nil, err
	}
	return gen.UpdateQuotas200JSONResponse{Body: quotasOut(q), Headers: gen.UpdateQuotas200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// GetClientQuotas returns one client's overrides.
func (s *server) GetClientQuotas(ctx context.Context, req gen.GetClientQuotasRequestObject) (gen.GetClientQuotasResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.quotaService()
	if err != nil {
		return nil, err
	}
	cid, err := parseClient(req.ClientId)
	if err != nil {
		return nil, err
	}
	q, err := svc.Get(ctx, p.TenantID, cid)
	if err != nil {
		return nil, err
	}
	return gen.GetClientQuotas200JSONResponse{Body: clientQuotasOut(cid, q), Headers: gen.GetClientQuotas200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// UpdateClientQuotas replaces one client's overrides.
func (s *server) UpdateClientQuotas(ctx context.Context, req gen.UpdateClientQuotasRequestObject) (gen.UpdateClientQuotasResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.quotaService()
	if err != nil {
		return nil, err
	}
	cid, err := parseClient(req.ClientId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	in, err := quotasIn(req.Body)
	if err != nil {
		return nil, err
	}
	q, err := svc.Put(ctx, p.TenantID, cid, actor, in)
	if err != nil {
		return nil, err
	}
	return gen.UpdateClientQuotas200JSONResponse{Body: clientQuotasOut(cid, q), Headers: gen.UpdateClientQuotas200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

func counterOut(m quota.Meter) gen.UsageCounter {
	return gen.UsageCounter{Used: m.Used, Limit: m.Limit}
}

// GetUsage reports the tenant's (or one of its clients') usage against the limits in force.
func (s *server) GetUsage(ctx context.Context, req gen.GetUsageRequestObject) (gen.GetUsageResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.quotaService()
	if err != nil {
		return nil, err
	}
	var cid id.ClientID
	if req.Params.ClientId != nil {
		if cid, err = parseClient(*req.Params.ClientId); err != nil {
			return nil, err
		}
	}
	u, err := svc.GetUsage(ctx, p.TenantID, cid)
	if err != nil {
		return nil, err
	}
	body := gen.Usage{
		MonthStart: u.MonthStart, StorageBytes: counterOut(u.Storage), TranscodeMilliseconds: counterOut(u.TranscodeMillis),
		ConcurrentSessions: counterOut(u.Sessions), RequestsPerMinute: u.RequestsPerMinute,
	}
	if !cid.IsZero() {
		c := cid.String()
		body.ClientId = &c
	}
	return gen.GetUsage200JSONResponse{Body: body, Headers: gen.GetUsage200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}
