package webhook

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
)

// Dispatcher sizes.
const (
	// Interval is how often the worker role looks for due deliveries.
	Interval = 2 * time.Second
	// batchSize deliveries are claimed per pass, delivered concurrently.
	batchSize = 32
	// lease is how long a claimed delivery is hidden from other workers. It exceeds the attempt
	// timeout plus the settle, so a live attempt is never claimed twice; a crashed one is retried
	// after it.
	lease = 2 * time.Minute
	// maxResponseRead is how much of a response is read for the excerpt.
	maxResponseRead = 1024
)

// Dispatcher claims due deliveries and POSTs them. Any number of workers may run one: a claim
// skips rows another worker holds.
type Dispatcher struct {
	Pool    *pgxpool.Pool
	Secrets *viewerauth.SecretBox
	// Client makes the requests. Required; it must be the SSRF-guarded client.
	Client *outbound.Client
	Log    *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
	// Unit returns a random number in [0, 1) for the retry jitter; defaults to math/rand.
	Unit func() float64
	// Timeout defaults to AttemptTimeout. Tests may shorten it.
	Timeout time.Duration
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// RunOnce claims the deliveries that are due and attempts them, and returns how many it attempted.
func (d *Dispatcher) RunOnce(ctx context.Context) (int, error) {
	repos := db.New(d.Pool)
	work, err := repos.ClaimWebhookDeliveries(ctx, d.now().UTC(), batchSize, lease)
	if err != nil || len(work) == 0 {
		return 0, err
	}
	var wg sync.WaitGroup
	for _, w := range work {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.deliver(ctx, w)
		}()
	}
	wg.Wait()
	return len(work), nil
}

// Run delivers until ctx is cancelled, passing again at once while a pass found a full batch.
func (d *Dispatcher) Run(ctx context.Context) {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		for {
			n, err := d.RunOnce(ctx)
			if err != nil && ctx.Err() == nil {
				log.ErrorContext(ctx, "webhook delivery pass failed", slog.String("code", errCode(err)))
			}
			if err != nil || n < batchSize || ctx.Err() != nil {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// deliver makes one attempt and settles it. A failure to open the secrets or to settle leaves the
// delivery claimed: it is due again when the lease ends and the attempt is not counted.
func (d *Dispatcher) deliver(ctx context.Context, w db.WebhookWork) {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	log = log.With(slog.String("tenant_id", w.TenantID.String()), slog.String("endpoint_id", w.EndpointID.String()),
		slog.String("event_id", w.EventID.String()), slog.String("kind", w.Kind))
	secrets, err := d.secrets(ctx, w)
	if err != nil {
		log.WarnContext(ctx, "webhook secret unavailable; the delivery will be retried", slog.String("code", errCode(err)))
		return
	}
	defer func() {
		for _, s := range secrets {
			clear(s)
		}
	}()
	body, err := Body(w.EventID, w.Kind, w.TenantID, w.OccurredAt, w.Data)
	if err != nil {
		log.ErrorContext(ctx, "webhook body could not be built")
		return
	}

	start := d.now().UTC()
	began := time.Now() // the duration is wall time, whatever clock the timestamps use
	status, class, excerpt := d.post(ctx, w, secrets, body, start)
	took := time.Since(began)

	number := w.Attempts + 1
	state, next := db.DeliveryPending, time.Time{}
	switch {
	case class == "":
		state = db.DeliverySucceeded
	case number >= MaxAttempts:
		state = db.DeliveryDead
	default:
		unit := rand.Float64
		if d.Unit != nil {
			unit = d.Unit
		}
		next = d.now().UTC().Add(Jitter(Delay(number), unit()))
	}
	attempt := db.WebhookAttempt{
		Number: number, At: start, StatusCode: status, DurationMs: int(took / time.Millisecond), Error: class, Excerpt: excerpt,
	}
	// The settle must land even when shutdown cancelled the request.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err = db.Tx(sctx, d.Pool, func(tx *db.Repos) error {
		_, err := tx.SettleWebhookAttempt(sctx, w, attempt, state, next)
		return err
	})
	if err != nil {
		log.WarnContext(ctx, "webhook attempt could not be recorded", slog.String("code", errCode(err)))
		return
	}
	switch state {
	case db.DeliveryDead:
		log.WarnContext(ctx, "webhook delivery dead-lettered", slog.Int("attempts", number), slog.String("failure", class))
	case db.DeliveryPending:
		log.InfoContext(ctx, "webhook attempt failed; will retry", slog.Int("attempt", number), slog.String("failure", class), slog.Int("status", status))
	}
}

// secrets returns the secrets a request is signed with: the current one, and the previous one for
// 24 hours after a rotation (so a receiver can switch over). The caller clears them.
func (d *Dispatcher) secrets(ctx context.Context, w db.WebhookWork) ([][]byte, error) {
	cur, err := d.Secrets.OpenFor(ctx, SecretPurpose(w.EndpointID), w.TenantID, w.Secret.Version, w.Secret.Envelope)
	if err != nil {
		return nil, err
	}
	out := [][]byte{cur}
	s := w.Secret
	if s.PrevVersion > 0 && len(s.PrevEnvelope) > 0 && s.SecretRotatedAt != nil && d.now().Before(s.SecretRotatedAt.Add(viewerauth.PreviousSecretWindow)) {
		if prev, err := d.Secrets.OpenFor(ctx, SecretPurpose(w.EndpointID), w.TenantID, s.PrevVersion, s.PrevEnvelope); err == nil {
			out = append(out, prev)
		}
	}
	return out, nil
}

// post sends the request and classifies the result: the status code (0 without a response), a
// failure class ("" for a 2xx) and the sanitized excerpt of the response.
func (d *Dispatcher) post(ctx context.Context, w db.WebhookWork, secrets [][]byte, body []byte, at time.Time) (status int, class, excerpt string) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = AttemptTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return 0, "bad_url", ""
	}
	msgID := w.EventID.String()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("webhook-id", msgID)
	req.Header.Set("webhook-timestamp", strconv.FormatInt(at.Unix(), 10))
	req.Header.Set("webhook-signature", viewerauth.SignatureHeader(secrets, msgID, at, body))

	res, err := d.Client.Do(req)
	if err != nil {
		return 0, transportClass(err), ""
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, maxResponseRead))
	excerpt = Excerpt(raw)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return res.StatusCode, "status", excerpt
	}
	return res.StatusCode, "", excerpt
}

func transportClass(err error) string {
	switch {
	case errors.Is(err, outbound.ErrBlockedAddress), errors.Is(err, outbound.ErrBadURL):
		return "blocked_address"
	case errors.Is(err, outbound.ErrRedirect):
		return "redirect"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "network"
}
