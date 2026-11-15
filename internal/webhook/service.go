package webhook

import (
	"context"
	"errors"
	"slices"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
)

// Audit actions written when a tenant changes its webhooks. They name the endpoint or delivery ID,
// never a URL or a secret.
const (
	AuditEndpointCreate       = "webhook_endpoint.create"
	AuditEndpointUpdate       = "webhook_endpoint.update"
	AuditEndpointDelete       = "webhook_endpoint.delete"
	AuditEndpointSecretRotate = "webhook_endpoint.secret.rotate" //nolint:gosec // an audit action name, not a credential
	AuditEndpointReplayDead   = "webhook_endpoint.replay_dead"
	AuditDeliveryReplay       = "webhook_delivery.replay"
)

// SecretPurpose is the purpose a webhook endpoint's secret is wrapped under. It names the endpoint,
// so an envelope copied to another endpoint of the same tenant does not open.
func SecretPurpose(endpoint id.WebhookEndpointID) string {
	return "webhook.endpoint_secret:" + endpoint.String()
}

// Service is the admin side of webhooks: endpoints and the delivery list. Safe for concurrent use.
type Service struct {
	pool    *pgxpool.Pool
	repos   *db.Repos
	secrets *viewerauth.SecretBox // nil without a KMS registry
	now     func() time.Time
}

// ServiceDeps are the collaborators of a Service.
type ServiceDeps struct {
	Pool *pgxpool.Pool
	// KMS wraps the endpoint secrets. Without it creating an endpoint and rotating a secret answer
	// dependency_unavailable.
	KMS *kms.Registry
	// Now defaults to time.Now.
	Now func() time.Time
}

// NewService builds a Service.
func NewService(d ServiceDeps) (*Service, error) {
	if d.Pool == nil {
		return nil, errors.New("webhook: a pool is required")
	}
	s := &Service{pool: d.Pool, repos: db.New(d.Pool), now: d.Now}
	if s.now == nil {
		s.now = time.Now
	}
	if d.KMS != nil {
		s.secrets = viewerauth.NewSecretBox(d.KMS)
	}
	return s, nil
}

// Now returns the service's clock, for the views that show whether a previous secret still signs.
func (s *Service) Now() time.Time { return s.now() }

// EndpointInput is what a tenant sets on an endpoint. A nil field is not set: on creation Enabled
// defaults to true and Events to every kind; on update it keeps the current value.
type EndpointInput struct {
	URL     *string
	Events  *[]string
	Enabled *bool
}

// Created is a new endpoint with its secret, shown once.
type Created struct {
	Endpoint db.WebhookEndpoint
	Secret   config.Secret // "whsec_" and base64 of 32 random bytes
}

func validateInput(in EndpointInput, creating bool) ([]string, error) {
	var fields []errs.FieldError
	bad := func(f, m string) { fields = append(fields, errs.FieldError{Field: f, Message: m}) }
	switch {
	case in.URL == nil:
		if creating {
			bad("url", "is required")
		}
	case len(*in.URL) > MaxEndpointURLChars:
		bad("url", "must be at most 2048 characters")
	default:
		if err := outbound.CheckURL(*in.URL); err != nil {
			bad("url", "must be an https URL without credentials, on a public address")
		}
	}
	var events []string
	if in.Events != nil {
		events = []string{}
		for _, k := range *in.Events {
			switch {
			case !db.ValidWebhookEventKind(k):
				bad("events", "contains an unknown event kind")
			case !slices.Contains(events, k):
				events = append(events, k)
			}
		}
	}
	if len(fields) > 0 {
		return nil, errs.Invalid("The request is invalid.", fields)
	}
	return events, nil
}

func (s *Service) audit(ctx context.Context, tx *db.Repos, tenant id.TenantID, actor auth.Actor, action, target string) error {
	_, err := tx.InsertAuditEvent(ctx, db.NewAuditEvent{
		TenantID: tenant, ClientID: actor.ClientID, APIKeyID: actor.KeyID, Action: action, Target: target, RequestID: actor.RequestID,
	})
	return err
}

// newSecret makes a secret and wraps it for the endpoint at the version. The caller clears the
// returned plain secret.
func (s *Service) newSecret(ctx context.Context, tenant id.TenantID, endpoint id.WebhookEndpointID, version int) (plain, envelope []byte, err error) {
	if s.secrets == nil {
		return nil, nil, errs.New(errs.DependencyUnavailable, "Key management is not available.")
	}
	plain, err = viewerauth.GenerateSecret()
	if err != nil {
		return nil, nil, errs.Wrap(errs.InternalError, "An internal error occurred.", err)
	}
	envelope, err = s.secrets.SealFor(ctx, SecretPurpose(endpoint), tenant, version, plain)
	if err != nil {
		clear(plain)
		return nil, nil, kms.ToAppError(err)
	}
	return plain, envelope, nil
}

// CreateEndpoint registers an endpoint and returns it with its signing secret, which is shown only
// here. A tenant may have at most db.MaxWebhookEndpoints.
func (s *Service) CreateEndpoint(ctx context.Context, tenant id.TenantID, actor auth.Actor, in EndpointInput) (Created, error) {
	events, err := validateInput(in, true)
	if err != nil {
		return Created{}, err
	}
	enabled := in.Enabled == nil || *in.Enabled
	eid := id.New[id.WebhookEndpointKind]()
	plain, envelope, err := s.newSecret(ctx, tenant, eid, 1)
	if err != nil {
		return Created{}, err
	}
	defer clear(plain)
	var ep db.WebhookEndpoint
	err = db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		if err := tx.LockWebhookEndpoints(ctx, tenant); err != nil {
			return err
		}
		n, err := tx.CountWebhookEndpoints(ctx, tenant)
		if err != nil {
			return err
		}
		if n >= db.MaxWebhookEndpoints {
			return errs.New(errs.Conflict, "The tenant already has the most webhook endpoints it may have (10). Delete one first.")
		}
		if ep, err = tx.InsertWebhookEndpoint(ctx, db.NewWebhookEndpoint{
			ID: eid, TenantID: tenant, URL: *in.URL, Events: events, Enabled: enabled, Envelope: envelope, At: s.now().UTC(),
		}); err != nil {
			return err
		}
		return s.audit(ctx, tx, tenant, actor, AuditEndpointCreate, eid.String())
	})
	if err != nil {
		return Created{}, err
	}
	return Created{Endpoint: ep, Secret: config.NewSecret(viewerauth.FormatSecret(plain))}, nil
}

// ListEndpoints returns the tenant's endpoints.
func (s *Service) ListEndpoints(ctx context.Context, tenant id.TenantID) ([]db.WebhookEndpoint, error) {
	return s.repos.ListWebhookEndpoints(ctx, tenant)
}

// GetEndpoint returns one endpoint, or not_found.
func (s *Service) GetEndpoint(ctx context.Context, tenant id.TenantID, endpoint id.WebhookEndpointID) (db.WebhookEndpoint, error) {
	return s.repos.GetWebhookEndpoint(ctx, tenant, endpoint)
}

// UpdateEndpoint changes the fields that are set.
func (s *Service) UpdateEndpoint(ctx context.Context, tenant id.TenantID, actor auth.Actor, endpoint id.WebhookEndpointID, in EndpointInput) (db.WebhookEndpoint, error) {
	events, err := validateInput(in, false)
	if err != nil {
		return db.WebhookEndpoint{}, err
	}
	var ep db.WebhookEndpoint
	err = db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		var err error
		ep, err = tx.UpdateWebhookEndpoint(ctx, tenant, endpoint, db.WebhookEndpointPatch{URL: in.URL, Events: events, Enabled: in.Enabled}, s.now().UTC())
		if err != nil {
			return err
		}
		return s.audit(ctx, tx, tenant, actor, AuditEndpointUpdate, endpoint.String())
	})
	return ep, err
}

// DeleteEndpoint deletes the endpoint, its deliveries and their attempts.
func (s *Service) DeleteEndpoint(ctx context.Context, tenant id.TenantID, actor auth.Actor, endpoint id.WebhookEndpointID) error {
	return db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		if err := tx.DeleteWebhookEndpoint(ctx, tenant, endpoint); err != nil {
			return err
		}
		return s.audit(ctx, tx, tenant, actor, AuditEndpointDelete, endpoint.String())
	})
}

// Rotated is the result of RotateSecret. Secret is shown once.
type Rotated struct {
	Secret  config.Secret
	Version int
	// PreviousValidUntil is when the previous secret stops signing.
	PreviousValidUntil time.Time
}

// RotateSecret makes a new secret for the endpoint and returns it once. The secret it replaces
// keeps signing, next to the new one, for 24 hours.
func (s *Service) RotateSecret(ctx context.Context, tenant id.TenantID, actor auth.Actor, endpoint id.WebhookEndpointID) (Rotated, error) {
	cur, err := s.repos.GetWebhookEndpoint(ctx, tenant, endpoint)
	if err != nil {
		return Rotated{}, err
	}
	version := cur.SecretVersion + 1
	plain, envelope, err := s.newSecret(ctx, tenant, endpoint, version)
	if err != nil {
		return Rotated{}, err
	}
	defer clear(plain)
	now := s.now().UTC().Truncate(time.Microsecond)
	err = db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		if _, err := tx.RotateWebhookEndpointSecret(ctx, tenant, endpoint, envelope, version, now); err != nil {
			return err
		}
		return s.audit(ctx, tx, tenant, actor, AuditEndpointSecretRotate, endpoint.String())
	})
	if err != nil {
		return Rotated{}, err
	}
	return Rotated{
		Secret: config.NewSecret(viewerauth.FormatSecret(plain)), Version: version,
		PreviousValidUntil: now.Add(viewerauth.PreviousSecretWindow),
	}, nil
}

// ListDeliveries returns a page of the tenant's deliveries, newest first.
func (s *Service) ListDeliveries(ctx context.Context, tenant id.TenantID, q db.DeliveryQuery) ([]db.WebhookDelivery, *db.EventCursor, error) {
	return s.repos.ListWebhookDeliveries(ctx, tenant, q)
}

// GetDelivery returns one delivery with its attempts, or not_found.
func (s *Service) GetDelivery(ctx context.Context, tenant id.TenantID, delivery uuid.UUID) (db.WebhookDelivery, []db.WebhookAttempt, error) {
	return s.repos.GetWebhookDelivery(ctx, tenant, delivery)
}

// ReplayDelivery puts a delivered or dead delivery back in the queue with a fresh attempt budget
// and returns it. A delivery that is still pending is a conflict.
func (s *Service) ReplayDelivery(ctx context.Context, tenant id.TenantID, actor auth.Actor, delivery uuid.UUID) (db.WebhookDelivery, error) {
	err := db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		if err := tx.ReplayWebhookDelivery(ctx, tenant, delivery, s.now().UTC()); err != nil {
			return err
		}
		return s.audit(ctx, tx, tenant, actor, AuditDeliveryReplay, delivery.String())
	})
	if err != nil {
		return db.WebhookDelivery{}, err
	}
	d, _, err := s.repos.GetWebhookDelivery(ctx, tenant, delivery)
	return d, err
}

// ReplayDead re-queues every dead delivery of the endpoint and returns how many.
func (s *Service) ReplayDead(ctx context.Context, tenant id.TenantID, actor auth.Actor, endpoint id.WebhookEndpointID) (int64, error) {
	var n int64
	err := db.Tx(ctx, s.pool, func(tx *db.Repos) error {
		if _, err := tx.GetWebhookEndpoint(ctx, tenant, endpoint); err != nil {
			return err
		}
		var err error
		if n, err = tx.ReplayDeadWebhookDeliveries(ctx, tenant, endpoint, s.now().UTC()); err != nil {
			return err
		}
		return s.audit(ctx, tx, tenant, actor, AuditEndpointReplayDead, endpoint.String())
	})
	return n, err
}

// errCode returns the registered code of err, for logs: never its text.
func errCode(err error) string {
	var e *errs.Error
	if errors.As(err, &e) {
		return string(e.Code)
	}
	return "unknown"
}
