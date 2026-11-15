package api

import (
	"context"
	"time"
	"uuid"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/webhook"
)

// defaultDeliveryPage is the page size of the deliveries list when the caller gives none.
const defaultDeliveryPage = 50

// The admin endpoints of webhooks (ADR 0045). The signing secret is returned by the creation and
// the rotation only, with Cache-Control: no-store; nothing here logs a URL or a secret.

func (s *server) webhookService() (*webhook.Service, error) {
	if s.webhooks == nil {
		return nil, errs.New(errs.DependencyUnavailable, "Webhooks are not available.")
	}
	return s.webhooks, nil
}

// parseEndpointID reads an endpoint ID from a path. A malformed one names nothing, so it is the
// same not_found as an unknown one.
func parseEndpointID(s string) (id.WebhookEndpointID, error) {
	e, err := id.Parse[id.WebhookEndpointKind](s)
	if err != nil {
		return id.WebhookEndpointID{}, errs.New(errs.NotFound, "No such webhook endpoint.")
	}
	return e, nil
}

func kindsOut(ks []string) []gen.WebhookEventKind {
	out := make([]gen.WebhookEventKind, len(ks))
	for i, k := range ks {
		out[i] = gen.WebhookEventKind(k)
	}
	return out
}

func kindsIn(ks *[]gen.WebhookEventKind) *[]string {
	if ks == nil {
		return nil
	}
	out := make([]string, len(*ks))
	for i, k := range *ks {
		out[i] = string(k)
	}
	return &out
}

func endpointOut(e db.WebhookEndpoint, now func() time.Time) gen.WebhookEndpoint {
	out := gen.WebhookEndpoint{
		Id: e.ID.String(), Url: e.URL, Events: kindsOut(e.Events), Enabled: e.Enabled, SecretVersion: e.SecretVersion,
		CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt,
	}
	if e.PrevSecretVersion > 0 && e.SecretRotatedAt != nil {
		if until := e.SecretRotatedAt.Add(viewerauth.PreviousSecretWindow); now().Before(until) {
			out.PreviousSecretValidUntil = &until
		}
	}
	return out
}

func deliveryOut(d db.WebhookDelivery) gen.WebhookDelivery {
	out := gen.WebhookDelivery{
		Id: openapi_types.UUID(d.ID), EndpointId: d.EndpointID.String(), EventId: openapi_types.UUID(d.EventID),
		Kind: gen.WebhookEventKind(d.Kind), Status: gen.WebhookDeliveryStatus(d.State), Attempts: d.Attempts,
		LastAttemptAt: d.LastAttemptAt, NextAttemptAt: d.NextAttemptAt, CompletedAt: d.CompletedAt, CreatedAt: d.CreatedAt,
	}
	if d.LastStatus > 0 {
		c := d.LastStatus
		out.LastStatusCode = &c
	}
	return out
}

func attemptOut(a db.WebhookAttempt) gen.WebhookAttempt {
	out := gen.WebhookAttempt{Number: a.Number, At: a.At, DurationMs: a.DurationMs}
	if a.StatusCode > 0 {
		c := a.StatusCode
		out.StatusCode = &c
	}
	if a.Error != "" {
		e := a.Error
		out.Error = &e
	}
	if a.Excerpt != "" {
		x := a.Excerpt
		out.Excerpt = &x
	}
	return out
}

// CreateWebhookEndpoint registers an endpoint and returns its secret once.
func (s *server) CreateWebhookEndpoint(ctx context.Context, req gen.CreateWebhookEndpointRequestObject) (gen.CreateWebhookEndpointResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.webhookService()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	c, err := svc.CreateEndpoint(ctx, p.TenantID, actor, webhook.EndpointInput{
		URL: &req.Body.Url, Events: kindsIn(req.Body.Events), Enabled: req.Body.Enabled,
	})
	if err != nil {
		return nil, err
	}
	return gen.CreateWebhookEndpoint201JSONResponse{
		Body:    gen.WebhookEndpointCreated{Endpoint: endpointOut(c.Endpoint, svc.Now), Secret: c.Secret.Reveal()},
		Headers: gen.CreateWebhookEndpoint201ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)},
	}, nil
}

// ListWebhookEndpoints lists the caller's tenant's endpoints.
func (s *server) ListWebhookEndpoints(ctx context.Context, _ gen.ListWebhookEndpointsRequestObject) (gen.ListWebhookEndpointsResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.webhookService()
	if err != nil {
		return nil, err
	}
	eps, err := svc.ListEndpoints(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}
	out := gen.WebhookEndpointList{Items: make([]gen.WebhookEndpoint, len(eps))}
	for i, e := range eps {
		out.Items[i] = endpointOut(e, svc.Now)
	}
	return gen.ListWebhookEndpoints200JSONResponse{Body: out, Headers: gen.ListWebhookEndpoints200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// GetWebhookEndpoint returns one endpoint.
func (s *server) GetWebhookEndpoint(ctx context.Context, req gen.GetWebhookEndpointRequestObject) (gen.GetWebhookEndpointResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.webhookService()
	if err != nil {
		return nil, err
	}
	eid, err := parseEndpointID(req.EndpointId)
	if err != nil {
		return nil, err
	}
	e, err := svc.GetEndpoint(ctx, p.TenantID, eid)
	if err != nil {
		return nil, err
	}
	return gen.GetWebhookEndpoint200JSONResponse{Body: endpointOut(e, svc.Now), Headers: gen.GetWebhookEndpoint200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// UpdateWebhookEndpoint changes an endpoint.
func (s *server) UpdateWebhookEndpoint(ctx context.Context, req gen.UpdateWebhookEndpointRequestObject) (gen.UpdateWebhookEndpointResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.webhookService()
	if err != nil {
		return nil, err
	}
	eid, err := parseEndpointID(req.EndpointId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	e, err := svc.UpdateEndpoint(ctx, p.TenantID, actor, eid, webhook.EndpointInput{
		URL: req.Body.Url, Events: kindsIn(req.Body.Events), Enabled: req.Body.Enabled,
	})
	if err != nil {
		return nil, err
	}
	return gen.UpdateWebhookEndpoint200JSONResponse{Body: endpointOut(e, svc.Now), Headers: gen.UpdateWebhookEndpoint200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// DeleteWebhookEndpoint deletes an endpoint with its deliveries.
func (s *server) DeleteWebhookEndpoint(ctx context.Context, req gen.DeleteWebhookEndpointRequestObject) (gen.DeleteWebhookEndpointResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.webhookService()
	if err != nil {
		return nil, err
	}
	eid, err := parseEndpointID(req.EndpointId)
	if err != nil {
		return nil, err
	}
	if err := svc.DeleteEndpoint(ctx, p.TenantID, actor, eid); err != nil {
		return nil, err
	}
	return gen.DeleteWebhookEndpoint204Response{Headers: gen.DeleteWebhookEndpoint204ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// RotateWebhookEndpointSecret makes a new secret and returns it once.
func (s *server) RotateWebhookEndpointSecret(ctx context.Context, req gen.RotateWebhookEndpointSecretRequestObject) (gen.RotateWebhookEndpointSecretResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.webhookService()
	if err != nil {
		return nil, err
	}
	eid, err := parseEndpointID(req.EndpointId)
	if err != nil {
		return nil, err
	}
	r, err := svc.RotateSecret(ctx, p.TenantID, actor, eid)
	if err != nil {
		return nil, err
	}
	return gen.RotateWebhookEndpointSecret200JSONResponse{
		Body:    gen.RotatedWebhookSecret{Secret: r.Secret.Reveal(), Version: r.Version, PreviousValidUntil: r.PreviousValidUntil},
		Headers: gen.RotateWebhookEndpointSecret200ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)},
	}, nil
}

// ReplayDeadWebhookDeliveries re-queues an endpoint's dead-lettered deliveries.
func (s *server) ReplayDeadWebhookDeliveries(ctx context.Context, req gen.ReplayDeadWebhookDeliveriesRequestObject) (gen.ReplayDeadWebhookDeliveriesResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.webhookService()
	if err != nil {
		return nil, err
	}
	eid, err := parseEndpointID(req.EndpointId)
	if err != nil {
		return nil, err
	}
	n, err := svc.ReplayDead(ctx, p.TenantID, actor, eid)
	if err != nil {
		return nil, err
	}
	return gen.ReplayDeadWebhookDeliveries200JSONResponse{
		Body: gen.ReplayedDeliveries{Replayed: n}, Headers: gen.ReplayDeadWebhookDeliveries200ResponseHeaders{XRequestId: requestID(ctx)},
	}, nil
}

// ListWebhookDeliveries lists the caller's tenant's deliveries, newest first.
func (s *server) ListWebhookDeliveries(ctx context.Context, req gen.ListWebhookDeliveriesRequestObject) (gen.ListWebhookDeliveriesResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.webhookService()
	if err != nil {
		return nil, err
	}
	q := db.DeliveryQuery{Limit: defaultDeliveryPage}
	var fields []errs.FieldError
	bad := func(field, msg string) { fields = append(fields, errs.FieldError{Field: field, Message: msg}) }
	if l := req.Params.Limit; l != nil {
		if *l < 1 || *l > db.MaxWebhookDeliveryPage {
			bad("limit", "must be between 1 and 100")
		} else {
			q.Limit = *l
		}
	}
	if req.Params.EndpointId != nil {
		e, err := id.Parse[id.WebhookEndpointKind](*req.Params.EndpointId)
		if err != nil {
			bad("endpoint_id", "is not a webhook endpoint ID")
		} else {
			q.EndpointID = e
		}
	}
	if req.Params.Status != nil {
		if !db.ValidDeliveryState(string(*req.Params.Status)) {
			bad("status", "is not a known status")
		} else {
			q.State = string(*req.Params.Status)
		}
	}
	if req.Params.Cursor != nil {
		c, err := db.ParseEventCursor(*req.Params.Cursor)
		if err != nil {
			bad("cursor", "is invalid")
		} else {
			q.Cursor = &c
		}
	}
	if len(fields) > 0 {
		return nil, errs.Invalid("The request is invalid.", fields)
	}
	page, next, err := svc.ListDeliveries(ctx, p.TenantID, q)
	if err != nil {
		return nil, err
	}
	out := gen.WebhookDeliveryList{Items: make([]gen.WebhookDelivery, len(page))}
	for i, d := range page {
		out.Items[i] = deliveryOut(d)
	}
	if next != nil {
		c := next.Encode()
		out.NextCursor = &c
	}
	return gen.ListWebhookDeliveries200JSONResponse{Body: out, Headers: gen.ListWebhookDeliveries200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// GetWebhookDelivery returns one delivery with its attempts.
func (s *server) GetWebhookDelivery(ctx context.Context, req gen.GetWebhookDeliveryRequestObject) (gen.GetWebhookDeliveryResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.webhookService()
	if err != nil {
		return nil, err
	}
	d, attempts, err := svc.GetDelivery(ctx, p.TenantID, uuid.UUID(req.DeliveryId))
	if err != nil {
		return nil, err
	}
	out := gen.WebhookDeliveryDetail{Delivery: deliveryOut(d), Attempts: make([]gen.WebhookAttempt, len(attempts))}
	for i, a := range attempts {
		out.Attempts[i] = attemptOut(a)
	}
	return gen.GetWebhookDelivery200JSONResponse{Body: out, Headers: gen.GetWebhookDelivery200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// ReplayWebhookDelivery re-queues one delivery.
func (s *server) ReplayWebhookDelivery(ctx context.Context, req gen.ReplayWebhookDeliveryRequestObject) (gen.ReplayWebhookDeliveryResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.webhookService()
	if err != nil {
		return nil, err
	}
	d, err := svc.ReplayDelivery(ctx, p.TenantID, actor, uuid.UUID(req.DeliveryId))
	if err != nil {
		return nil, err
	}
	return gen.ReplayWebhookDelivery202JSONResponse{Body: deliveryOut(d), Headers: gen.ReplayWebhookDelivery202ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}
