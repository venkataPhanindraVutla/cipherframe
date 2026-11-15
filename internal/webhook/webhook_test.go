package webhook

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
)

// The published Standard Webhooks test vector: the signature header every conforming sender
// produces for this secret, message ID, timestamp and body.
func TestSignatureMatchesTheStandardWebhooksVector(t *testing.T) {
	secret, err := base64.StdEncoding.DecodeString(strings.TrimPrefix("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", viewerauth.SecretPrefix))
	if err != nil {
		t.Fatal(err)
	}
	got := viewerauth.Signature(secret, "msg_p5jXN8AQM9LWM0D4loKWxJek", time.Unix(1614265330, 0), []byte(`{"test": 2432232314}`))
	if want := "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="; got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
}

func TestDelayIsAnExponentialScheduleOverAboutADay(t *testing.T) {
	var total time.Duration
	prev := time.Duration(0)
	for n := 1; n < MaxAttempts; n++ {
		d := Delay(n)
		if d <= prev {
			t.Errorf("Delay(%d) = %v does not grow from %v", n, d, prev)
		}
		prev = d
		total += d
	}
	if total < 20*time.Hour || total > 24*time.Hour {
		t.Errorf("the schedule spans %v, want about a day", total)
	}
	if Delay(0) != Delay(1) || Delay(99) != Delay(MaxAttempts-1) {
		t.Error("Delay is not clamped at both ends")
	}
}

func TestJitterStaysWithinTwentyPercent(t *testing.T) {
	d := 10 * time.Minute
	if got := Jitter(d, 0); got != 8*time.Minute {
		t.Errorf("Jitter(d, 0) = %v", got)
	}
	if got := Jitter(d, 0.5); got != d {
		t.Errorf("Jitter(d, 0.5) = %v", got)
	}
	if got := Jitter(d, 0.999999); got < d || got > 12*time.Minute {
		t.Errorf("Jitter(d, ~1) = %v", got)
	}
}

func TestBodyCarriesIDsAndStatesOnly(t *testing.T) {
	tenant := id.New[id.TenantKind]()
	asset := uuid.NewV7()
	event := uuid.NewV7()
	at := time.Date(2026, 11, 14, 10, 0, 0, 123, time.UTC)
	data := map[string]any{
		"asset_id": asset.String(), "state": "failed", "failure_code": "unsupported_codec", "viewer_id": nil, "session": nil,
	}
	b, err := Body(event, "asset.failed", tenant, at, data)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Body(event, "asset.failed", tenant, at, data)
	if !bytes.Equal(b, again) {
		t.Error("the body differs between renderings, so a retry would sign other bytes")
	}
	var got struct {
		ID         string         `json:"id"`
		Type       string         `json:"type"`
		OccurredAt string         `json:"occurred_at"`
		TenantID   string         `json:"tenant_id"`
		Data       map[string]any `json:"data"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != event.String() || got.Type != "asset.failed" || got.TenantID != tenant.String() || got.OccurredAt == "" {
		t.Errorf("envelope = %+v", got)
	}
	if got.Data["asset_id"] != id.FromUUID[id.AssetKind](asset).String() {
		t.Errorf("asset_id = %v, want the prefixed ID", got.Data["asset_id"])
	}
	if _, has := got.Data["viewer_id"]; has {
		t.Error("an absent value is sent as null instead of being left out")
	}
	// Nothing a body can hold names a viewer's address, a user agent, a file, a key or a token.
	for _, banned := range []string{"ip", "user_agent", "ua", "address", "filename", "file_name", "name", "key", "token", "url"} {
		for k := range got.Data {
			if k == banned || strings.Contains(k, "token") || strings.Contains(k, "address") {
				t.Errorf("payload field %q", k)
			}
		}
	}
}

func TestExcerptIsSmallPrintableAndOneLine(t *testing.T) {
	got := Excerpt([]byte("  bad\x00 gateway\r\n\t\xff<html>  "))
	if got != "bad gateway <html>" {
		t.Errorf("Excerpt = %q", got)
	}
	long := Excerpt(bytes.Repeat([]byte("abcdefghij "), 100))
	if len(long) > MaxExcerptChars {
		t.Errorf("len = %d", len(long))
	}
	for _, c := range []byte(long) {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("non-printable byte %#x", c)
		}
	}
	if Excerpt(nil) != "" {
		t.Error("an empty body has an empty excerpt")
	}
}
