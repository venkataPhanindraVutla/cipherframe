// Package webhook delivers Cipherframe's events to the endpoints a tenant registered (M7-5, ADR
// 0045).
//
// An event is written to the outbox (webhook_events, with one webhook_deliveries row per matching
// endpoint) by database triggers in the transaction of the state change that caused it, so an
// event exists if and only if the change committed. The Dispatcher claims due deliveries and POSTs
// them through the SSRF-guarded outbound client, signed with the Standard Webhooks scheme (the
// same helpers as the viewer-authorization callback). Delivery is at-least-once: a receiver
// deduplicates on the event ID, which is also the webhook-id header.
//
// Payloads carry IDs and states only. Nothing in this package logs a URL, a secret, a header or a
// response body.
package webhook

import (
	"encoding/json"
	"strings"
	"time"
	"uuid"

	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// Delivery limits (ADR 0045).
const (
	// AttemptTimeout bounds one request: connect, send and read the response.
	AttemptTimeout = 10 * time.Second
	// MaxAttempts is the number of attempts before a delivery is dead-lettered. With the schedule
	// below the last one is made about 22 hours after the first.
	MaxAttempts = 12
	// MaxExcerptChars is the longest piece of a response that is stored.
	MaxExcerptChars = 200
	// UserAgent is sent with every request.
	UserAgent = "cipherframe-webhooks"
	// MaxEndpointURLChars is the longest endpoint URL.
	MaxEndpointURLChars = 2048
)

// schedule is the wait before each retry: schedule[n-1] follows attempt n. Twelve attempts make
// eleven waits, 21 hours and 52 minutes in all, before jitter.
var schedule = [MaxAttempts - 1]time.Duration{
	10 * time.Second, 30 * time.Second, time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 2 * time.Hour, 4 * time.Hour, 6 * time.Hour, 8 * time.Hour,
}

// Delay returns the wait after the n-th failed attempt (n from 1) before the next one, without
// jitter.
func Delay(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	return schedule[min(n, len(schedule))-1]
}

// Jitter spreads d by up to 20% either way: unit is a random number in [0, 1), so a retry storm of
// deliveries that failed together does not hit the endpoint together again.
func Jitter(d time.Duration, unit float64) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*unit))
}

// Envelope is the JSON body of every webhook request.
type envelope struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	OccurredAt string         `json:"occurred_at"`
	TenantID   string         `json:"tenant_id"`
	Data       map[string]any `json:"data"`
}

// Body renders the request body of an event: the envelope with the event's data, where the raw
// UUID of the asset becomes its prefixed ID and absent values are left out. The result is the same
// for every attempt and every endpoint, so every attempt signs the same bytes.
func Body(eventID uuid.UUID, kind string, tenant id.TenantID, occurred time.Time, data map[string]any) ([]byte, error) {
	out := make(map[string]any, len(data))
	for k, v := range data {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && k == "asset_id" {
			if u, err := uuid.Parse(s); err == nil {
				v = id.FromUUID[id.AssetKind](u).String()
			}
		}
		out[k] = v
	}
	return json.Marshal(envelope{
		ID: eventID.String(), Type: kind, OccurredAt: occurred.UTC().Format(time.RFC3339Nano), TenantID: tenant.String(), Data: out,
	})
}

// Excerpt reduces the start of a response body to a small, single-line, printable-ASCII piece for
// the attempt record: everything else becomes a space, runs of spaces collapse, and it is cut to
// MaxExcerptChars.
func Excerpt(raw []byte) string {
	var b strings.Builder
	space := true
	for _, c := range raw {
		if c < 0x20 || c > 0x7e {
			c = ' '
		}
		if c == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		b.WriteByte(c)
		if b.Len() >= MaxExcerptChars {
			break
		}
	}
	return strings.TrimSpace(b.String())
}
