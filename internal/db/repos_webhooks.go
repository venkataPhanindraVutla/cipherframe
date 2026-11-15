package db

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// The webhook event kinds (the webhook_events and webhook_endpoints CHECK constraints list the
// same). The triggers of migration 00024 write them.
const (
	WebhookAssetReady       = "asset.ready"
	WebhookAssetFailed      = "asset.failed"
	WebhookAssetDeleted     = "asset.deleted"
	WebhookSessionRevoked   = "session.revoked"
	WebhookSessionAnomaly   = "session.anomaly"
	WebhookRetentionExpired = "retention.expired"
)

// WebhookEventKinds lists every kind, in the order the documentation uses.
var WebhookEventKinds = []string{
	WebhookAssetReady, WebhookAssetFailed, WebhookAssetDeleted, WebhookSessionRevoked, WebhookSessionAnomaly, WebhookRetentionExpired,
}

// ValidWebhookEventKind reports whether k is a webhook event kind.
func ValidWebhookEventKind(k string) bool { return slices.Contains(WebhookEventKinds, k) }

// The states of a webhook delivery.
const (
	DeliveryPending   = "pending"
	DeliverySucceeded = "succeeded"
	DeliveryDead      = "dead"
)

// ValidDeliveryState reports whether s is a delivery state.
func ValidDeliveryState(s string) bool {
	return s == DeliveryPending || s == DeliverySucceeded || s == DeliveryDead
}

// MaxWebhookEndpoints is how many endpoints a tenant may register.
const MaxWebhookEndpoints = 10

// WebhookEndpoint is a row of webhook_endpoints. The envelopes are the wrapped signing secrets:
// ciphertext, but still never placed in a response or a log.
type WebhookEndpoint struct {
	ID                 id.WebhookEndpointID
	TenantID           id.TenantID
	URL                string
	Events             []string // empty: every kind
	Enabled            bool
	SecretEnvelope     []byte
	SecretVersion      int
	PrevSecretEnvelope []byte
	PrevSecretVersion  int // 0: none
	SecretRotatedAt    *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func webhookEndpointFromRow(r dbgen.WebhookEndpoint) WebhookEndpoint {
	e := WebhookEndpoint{
		ID: fromPG[id.WebhookEndpointKind](r.ID), TenantID: fromPG[id.TenantKind](r.TenantID), URL: r.Url,
		Events: append([]string{}, r.Events...), Enabled: r.Enabled, SecretEnvelope: r.SecretEnvelope,
		SecretVersion: int(r.SecretVersion), PrevSecretEnvelope: r.PrevSecretEnvelope,
		SecretRotatedAt: utcPtr(r.SecretRotatedAt), CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(),
	}
	if r.PrevSecretVersion != nil {
		e.PrevSecretVersion = int(*r.PrevSecretVersion)
	}
	return e
}

// LockWebhookEndpoints takes a transaction-scoped advisory lock on one tenant's endpoint set, so
// the cap holds under concurrent creation. Use it inside Tx before CountWebhookEndpoints.
func (r *Repos) LockWebhookEndpoints(ctx context.Context, tenantID id.TenantID) error {
	if tenantID.IsZero() {
		return errs.New(errs.InvalidRequest, "a required identifier is missing")
	}
	return mapError(r.q.LockWebhookEndpoints(ctx, "cipherframe.webhook_endpoints:"+tenantID.String()))
}

// CountWebhookEndpoints returns how many endpoints the tenant has.
func (r *Repos) CountWebhookEndpoints(ctx context.Context, tenantID id.TenantID) (int, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return 0, err
	}
	n, err := r.q.CountWebhookEndpoints(ctx, tid)
	return int(n), mapError(err)
}

// NewWebhookEndpoint is the input of InsertWebhookEndpoint. Envelope is the secret, wrapped under
// secret version 1.
type NewWebhookEndpoint struct {
	ID       id.WebhookEndpointID
	TenantID id.TenantID
	URL      string
	Events   []string
	Enabled  bool
	Envelope []byte
	At       time.Time
}

// InsertWebhookEndpoint stores an endpoint.
func (r *Repos) InsertWebhookEndpoint(ctx context.Context, in NewWebhookEndpoint) (WebhookEndpoint, error) {
	eid, err := requirePG(in.ID)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	tid, err := requirePG(in.TenantID)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	if len(in.Envelope) == 0 {
		return WebhookEndpoint{}, errs.New(errs.InvalidRequest, "invalid webhook secret")
	}
	row, err := r.q.InsertWebhookEndpoint(ctx, dbgen.InsertWebhookEndpointParams{
		ID: eid, TenantID: tid, Url: in.URL, Events: nonNilStrings(in.Events), Enabled: in.Enabled,
		SecretEnvelope: in.Envelope, At: in.At.UTC(),
	})
	if err != nil {
		return WebhookEndpoint{}, mapError(err)
	}
	return webhookEndpointFromRow(row), nil
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ListWebhookEndpoints returns the tenant's endpoints, oldest first.
func (r *Repos) ListWebhookEndpoints(ctx context.Context, tenantID id.TenantID) ([]WebhookEndpoint, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListWebhookEndpoints(ctx, tid)
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]WebhookEndpoint, len(rows))
	for i, row := range rows {
		out[i] = webhookEndpointFromRow(row)
	}
	return out, nil
}

// GetWebhookEndpoint returns the tenant's endpoint, or not_found (also for another tenant's).
func (r *Repos) GetWebhookEndpoint(ctx context.Context, tenantID id.TenantID, endpointID id.WebhookEndpointID) (WebhookEndpoint, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	eid, err := requirePG(endpointID)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	row, err := r.q.GetWebhookEndpoint(ctx, dbgen.GetWebhookEndpointParams{TenantID: tid, ID: eid})
	if err != nil {
		return WebhookEndpoint{}, mapError(err)
	}
	return webhookEndpointFromRow(row), nil
}

// WebhookEndpointPatch changes the fields that are set: a nil URL or Enabled, and a nil Events,
// stay as they are (an empty, non-nil Events means every kind).
type WebhookEndpointPatch struct {
	URL     *string
	Events  []string
	Enabled *bool
}

// UpdateWebhookEndpoint applies the patch and returns the endpoint, or not_found.
func (r *Repos) UpdateWebhookEndpoint(ctx context.Context, tenantID id.TenantID, endpointID id.WebhookEndpointID, p WebhookEndpointPatch, at time.Time) (WebhookEndpoint, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	eid, err := requirePG(endpointID)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	row, err := r.q.UpdateWebhookEndpoint(ctx, dbgen.UpdateWebhookEndpointParams{
		Url: p.URL, Events: p.Events, Enabled: p.Enabled, At: at.UTC(), TenantID: tid, ID: eid,
	})
	if err != nil {
		return WebhookEndpoint{}, mapError(err)
	}
	return webhookEndpointFromRow(row), nil
}

// RotateWebhookEndpointSecret stores envelope as the endpoint's secret of the given version, which
// must be the current version plus one, and keeps the secret it replaces as the previous one. A
// concurrent rotation is a conflict.
func (r *Repos) RotateWebhookEndpointSecret(ctx context.Context, tenantID id.TenantID, endpointID id.WebhookEndpointID, envelope []byte, version int, at time.Time) (WebhookEndpoint, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	eid, err := requirePG(endpointID)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	if len(envelope) == 0 || version < 2 {
		return WebhookEndpoint{}, errs.New(errs.InvalidRequest, "invalid webhook secret")
	}
	row, err := r.q.RotateWebhookEndpointSecret(ctx, dbgen.RotateWebhookEndpointSecretParams{
		TenantID: tid, ID: eid, Envelope: envelope, Version: int32(version), At: at.UTC(), //nolint:gosec // a small counter
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return WebhookEndpoint{}, errs.New(errs.Conflict, "The secret was rotated concurrently. Try again.")
	}
	if err != nil {
		return WebhookEndpoint{}, mapError(err)
	}
	return webhookEndpointFromRow(row), nil
}

// DeleteWebhookEndpoint deletes the endpoint with its deliveries and attempts, or returns
// not_found.
func (r *Repos) DeleteWebhookEndpoint(ctx context.Context, tenantID id.TenantID, endpointID id.WebhookEndpointID) error {
	tid, err := requirePG(tenantID)
	if err != nil {
		return err
	}
	eid, err := requirePG(endpointID)
	if err != nil {
		return err
	}
	n, err := r.q.DeleteWebhookEndpoint(ctx, dbgen.DeleteWebhookEndpointParams{TenantID: tid, ID: eid})
	if err != nil {
		return mapError(err)
	}
	if n == 0 {
		return errs.New(errs.NotFound, "resource not found")
	}
	return nil
}

// WebhookWork is one claimed delivery with what an attempt needs: the event and the endpoint.
type WebhookWork struct {
	DeliveryID uuid.UUID
	TenantID   id.TenantID
	EventID    uuid.UUID
	EndpointID id.WebhookEndpointID
	// Attempts is how many attempts were made before this one.
	Attempts   int
	Kind       string
	Data       map[string]any
	OccurredAt time.Time
	URL        string
	Secret     WebhookSecrets
}

// WebhookSecrets are the wrapped signing secrets of an endpoint.
type WebhookSecrets struct {
	Envelope        []byte
	Version         int
	PrevEnvelope    []byte
	PrevVersion     int
	SecretRotatedAt *time.Time
}

// ClaimWebhookDeliveries takes up to limit deliveries that are due at now, from enabled endpoints,
// and defers each by lease: a delivery whose attempt never settles (a crash) is due again after it.
func (r *Repos) ClaimWebhookDeliveries(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]WebhookWork, error) {
	if limit < 1 || lease <= 0 {
		return nil, errs.New(errs.InvalidRequest, "invalid claim")
	}
	rows, err := r.q.ClaimWebhookDeliveries(ctx, dbgen.ClaimWebhookDeliveriesParams{
		Now: now.UTC(), MaxRows: int32(limit), LeaseSeconds: int32(lease / time.Second), //nolint:gosec // bounded by the caller
	})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]WebhookWork, len(rows))
	for i, row := range rows {
		data := map[string]any{}
		_ = json.Unmarshal(row.Data, &data) // written by the triggers; a bad row reads as empty
		w := WebhookWork{
			DeliveryID: uuid.UUID(row.ID.Bytes), TenantID: fromPG[id.TenantKind](row.TenantID),
			EventID: uuid.UUID(row.EventID.Bytes), EndpointID: fromPG[id.WebhookEndpointKind](row.EndpointID),
			Attempts: int(row.Attempts), Kind: row.Kind, Data: data, OccurredAt: row.OccurredAt.UTC(), URL: row.Url,
			Secret: WebhookSecrets{
				Envelope: row.SecretEnvelope, Version: int(row.SecretVersion), PrevEnvelope: row.PrevSecretEnvelope,
				SecretRotatedAt: utcPtr(row.SecretRotatedAt),
			},
		}
		if row.PrevSecretVersion != nil {
			w.Secret.PrevVersion = int(*row.PrevSecretVersion)
		}
		out[i] = w
	}
	return out, nil
}

// WebhookAttempt is what one attempt got back. Error is a short failure class ("timeout",
// "status"...), empty on success. Excerpt is a small sanitized piece of the response.
type WebhookAttempt struct {
	Number     int
	At         time.Time
	StatusCode int // 0: no response
	DurationMs int
	Error      string
	Excerpt    string
}

// SettleWebhookAttempt records an attempt and moves the delivery on in one statement pair; call it
// inside Tx. state is pending (with the time of the next attempt), succeeded or dead. It returns
// false, and records nothing, when the delivery was settled or replayed in the meantime.
func (r *Repos) SettleWebhookAttempt(ctx context.Context, w WebhookWork, a WebhookAttempt, state string, next time.Time) (bool, error) {
	did := rawToPG(w.DeliveryID)
	tid, err := requirePG(w.TenantID)
	if err != nil {
		return false, err
	}
	if !ValidDeliveryState(state) {
		return false, errs.New(errs.InternalError, "An internal error occurred.")
	}
	var status *int32
	if a.StatusCode > 0 {
		s := int32(a.StatusCode) //nolint:gosec // an HTTP status
		status = &s
	}
	var nextAt *time.Time
	if state == DeliveryPending {
		n := next.UTC()
		nextAt = &n
	}
	n, err := r.q.SettleWebhookDelivery(ctx, dbgen.SettleWebhookDeliveryParams{
		State: state, NextAttemptAt: nextAt, StatusCode: status, At: a.At.UTC(), ID: did, Attempts: int32(w.Attempts), //nolint:gosec // a small counter
	})
	if err != nil || n == 0 {
		return false, mapError(err)
	}
	err = r.q.InsertWebhookAttempt(ctx, dbgen.InsertWebhookAttemptParams{
		DeliveryID: did, TenantID: tid, Number: int32(a.Number), At: a.At.UTC(), StatusCode: status, //nolint:gosec // a small counter
		DurationMs: int32(a.DurationMs), Error: strPtr(a.Error), Excerpt: a.Excerpt, //nolint:gosec // bounded by the timeout
	})
	return err == nil, mapError(err)
}

// WebhookDelivery is one delivery of one event to one endpoint, as the admin API reports it.
type WebhookDelivery struct {
	ID            uuid.UUID
	EndpointID    id.WebhookEndpointID
	EventID       uuid.UUID
	Kind          string
	State         string
	Attempts      int
	LastStatus    int // 0: none
	LastAttemptAt *time.Time
	NextAttemptAt time.Time
	CompletedAt   *time.Time
	CreatedAt     time.Time
}

func webhookDeliveryFrom(id_, endpoint, event pgtype.UUID, kind, state string, attempts int32, last *int32, lastAt *time.Time, next time.Time, done *time.Time, created time.Time) WebhookDelivery {
	d := WebhookDelivery{
		ID: uuid.UUID(id_.Bytes), EndpointID: fromPG[id.WebhookEndpointKind](endpoint), EventID: uuid.UUID(event.Bytes),
		Kind: kind, State: state, Attempts: int(attempts), LastAttemptAt: utcPtr(lastAt), NextAttemptAt: next.UTC(),
		CompletedAt: utcPtr(done), CreatedAt: created.UTC(),
	}
	if last != nil {
		d.LastStatus = int(*last)
	}
	return d
}

// MaxWebhookDeliveryPage is the largest page of the deliveries list.
const MaxWebhookDeliveryPage = 100

// DeliveryQuery filters and pages the deliveries list. A zero EndpointID and an empty State mean no
// filter. Limit is 1 to MaxWebhookDeliveryPage.
type DeliveryQuery struct {
	EndpointID id.WebhookEndpointID
	State      string
	Cursor     *EventCursor // At is the delivery's creation time
	Limit      int
}

// ListWebhookDeliveries returns the tenant's deliveries, newest first, and the cursor of the next
// page (nil on the last page).
func (r *Repos) ListWebhookDeliveries(ctx context.Context, tenantID id.TenantID, q DeliveryQuery) ([]WebhookDelivery, *EventCursor, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, nil, err
	}
	if q.Limit < 1 || q.Limit > MaxWebhookDeliveryPage || (q.State != "" && !ValidDeliveryState(q.State)) {
		return nil, nil, errs.New(errs.InvalidRequest, "invalid page")
	}
	cursorAt, cursorID := time.Date(9000, 1, 1, 0, 0, 0, 0, time.UTC), uuid.Max()
	if q.Cursor != nil {
		cursorAt, cursorID = q.Cursor.At, q.Cursor.ID
	}
	rows, err := r.q.ListWebhookDeliveries(ctx, dbgen.ListWebhookDeliveriesParams{
		TenantID: tid, EndpointID: toPG(q.EndpointID), State: strPtr(q.State), CursorAt: cursorAt, CursorID: rawToPG(cursorID),
		MaxRows: int32(q.Limit + 1), //nolint:gosec // bounded by MaxWebhookDeliveryPage
	})
	if err != nil {
		return nil, nil, mapError(err)
	}
	out := make([]WebhookDelivery, len(rows))
	for i, x := range rows {
		out[i] = webhookDeliveryFrom(x.ID, x.EndpointID, x.EventID, x.Kind, x.State, x.Attempts, x.LastStatus, x.LastAttemptAt, x.NextAttemptAt, x.CompletedAt, x.CreatedAt)
	}
	if len(out) <= q.Limit {
		return out, nil, nil
	}
	out = out[:q.Limit]
	last := out[len(out)-1]
	return out, &EventCursor{At: last.CreatedAt, ID: last.ID}, nil
}

// GetWebhookDelivery returns the tenant's delivery with its attempts, or not_found.
func (r *Repos) GetWebhookDelivery(ctx context.Context, tenantID id.TenantID, deliveryID uuid.UUID) (WebhookDelivery, []WebhookAttempt, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return WebhookDelivery{}, nil, err
	}
	did := rawToPG(deliveryID)
	x, err := r.q.GetWebhookDelivery(ctx, dbgen.GetWebhookDeliveryParams{TenantID: tid, ID: did})
	if err != nil {
		return WebhookDelivery{}, nil, mapError(err)
	}
	rows, err := r.q.ListWebhookAttempts(ctx, dbgen.ListWebhookAttemptsParams{TenantID: tid, DeliveryID: did})
	if err != nil {
		return WebhookDelivery{}, nil, mapError(err)
	}
	attempts := make([]WebhookAttempt, len(rows))
	for i, a := range rows {
		attempts[i] = WebhookAttempt{Number: int(a.Number), At: a.At.UTC(), DurationMs: int(a.DurationMs), Error: strVal(a.Error), Excerpt: a.Excerpt}
		if a.StatusCode != nil {
			attempts[i].StatusCode = int(*a.StatusCode)
		}
	}
	d := webhookDeliveryFrom(x.ID, x.EndpointID, x.EventID, x.Kind, x.State, x.Attempts, x.LastStatus, x.LastAttemptAt, x.NextAttemptAt, x.CompletedAt, x.CreatedAt)
	return d, attempts, nil
}

// ReplayWebhookDelivery puts a settled delivery back in the queue with a fresh attempt budget. A
// delivery that is still pending is a conflict; an unknown one is not_found.
func (r *Repos) ReplayWebhookDelivery(ctx context.Context, tenantID id.TenantID, deliveryID uuid.UUID, now time.Time) error {
	tid, err := requirePG(tenantID)
	if err != nil {
		return err
	}
	n, err := r.q.ReplayWebhookDelivery(ctx, dbgen.ReplayWebhookDeliveryParams{Now: now.UTC(), TenantID: tid, ID: rawToPG(deliveryID)})
	if err != nil {
		return mapError(err)
	}
	if n == 0 {
		if _, _, err := r.GetWebhookDelivery(ctx, tenantID, deliveryID); err != nil {
			return err
		}
		return errs.New(errs.Conflict, "The delivery is still pending.")
	}
	return nil
}

// ReplayDeadWebhookDeliveries re-queues every dead delivery of the endpoint and returns how many.
func (r *Repos) ReplayDeadWebhookDeliveries(ctx context.Context, tenantID id.TenantID, endpointID id.WebhookEndpointID, now time.Time) (int64, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return 0, err
	}
	eid, err := requirePG(endpointID)
	if err != nil {
		return 0, err
	}
	n, err := r.q.ReplayDeadWebhookDeliveries(ctx, dbgen.ReplayDeadWebhookDeliveriesParams{Now: now.UTC(), TenantID: tid, EndpointID: eid})
	return n, mapError(err)
}

// DeleteWebhookEventsBefore deletes up to batch webhook events older than cutoff, with their
// deliveries and attempts, and returns how many events it deleted. Call it until it returns less
// than batch (retention, ADR 0045).
func (r *Repos) DeleteWebhookEventsBefore(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
	if batch < 1 {
		return 0, errs.New(errs.InvalidRequest, "invalid batch size")
	}
	n, err := r.q.DeleteWebhookEventsBefore(ctx, dbgen.DeleteWebhookEventsBeforeParams{Cutoff: cutoff.UTC(), Batch: int32(batch)}) //nolint:gosec // bounded by the caller
	return n, mapError(err)
}
