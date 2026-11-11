package viewerauth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
)

// Callback limits (ADR 0029).
const (
	// CallbackTimeout is the whole budget of one callback: connect, request and response.
	CallbackTimeout = 2 * time.Second
	// MaxCallbackResponseBytes is the largest response body read.
	MaxCallbackResponseBytes = 8 << 10
	// MaxTicketBytes is the longest ticket the browser may send.
	MaxTicketBytes = 2048
	// CallbackType is the "type" of the request body.
	CallbackType = "playback.authorize"
	// PreviousSecretWindow is how long after a rotation the previous secret still signs.
	PreviousSecretWindow = 24 * time.Hour
)

// Denial reasons for a callback.
const (
	ReasonCallbackFailed   = "callback_failed"
	ReasonCallbackStatus   = "callback_status"
	ReasonCallbackResponse = "callback_response"
	ReasonCallbackDenied   = "callback_denied"
	ReasonCallbackViewer   = "callback_viewer"
)

// CallbackRequest is what the callback is asked about.
type CallbackRequest struct {
	TenantID  string
	AssetID   string
	Ticket    string
	RequestID string
}

// callbackBody is the JSON the tenant receives.
type callbackBody struct {
	Type      string `json:"type"`
	TenantID  string `json:"tenant_id"`
	AssetID   string `json:"asset_id"`
	Ticket    string `json:"ticket"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

// callbackAnswer is the JSON the tenant must answer with. Strict decoding: an unknown field, a
// missing "allow", a wrong type or trailing data is a denial.
type callbackAnswer struct {
	Allow    *bool   `json:"allow"`
	ViewerID *string `json:"viewer_id"`
}

// Authorizer asks a tenant's callback whether a viewer may start a session.
type Authorizer struct {
	client         *outbound.Client
	validateViewer func(string) error
	now            func() time.Time
	timeout        time.Duration
}

// AuthorizerOptions configure an Authorizer.
type AuthorizerOptions struct {
	// Client makes the request. Required.
	Client *outbound.Client
	// ValidateViewer checks the viewer_id of the answer. Required.
	ValidateViewer func(string) error
	// Now defaults to time.Now.
	Now func() time.Time
	// Timeout defaults to CallbackTimeout. Tests may shorten it; production does not.
	Timeout time.Duration
}

// NewAuthorizer returns an Authorizer.
func NewAuthorizer(o AuthorizerOptions) (*Authorizer, error) {
	if o.Client == nil || o.ValidateViewer == nil {
		return nil, errors.New("viewerauth: a client and a viewer validator are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Timeout <= 0 {
		o.Timeout = CallbackTimeout
	}
	return &Authorizer{client: o.Client, validateViewer: o.ValidateViewer, now: o.Now, timeout: o.Timeout}, nil
}

// Authorize POSTs the request to url, signed with every secret in secrets (the current one, and the
// previous one during its overlap), and returns the viewer ID the tenant answered with. Only HTTP
// 200 with {"allow": true, "viewer_id": "..."} grants. Every other outcome (a timeout, a network
// error, a redirect, another status, a body that is too long or malformed, allow false, a bad
// viewer_id) is a *DenyError: the endpoint fails closed. The answer is never cached.
func (a *Authorizer) Authorize(ctx context.Context, url string, secrets [][]byte, r CallbackRequest) (string, error) {
	if len(secrets) == 0 {
		return "", deny(ReasonConfig)
	}
	now := a.now().UTC()
	body, err := json.Marshal(callbackBody{
		Type: CallbackType, TenantID: r.TenantID, AssetID: r.AssetID, Ticket: r.Ticket,
		RequestID: r.RequestID, Timestamp: now.Format(time.RFC3339),
	})
	if err != nil {
		return "", deny(ReasonCallbackFailed)
	}
	msgID, err := newMessageID()
	if err != nil {
		return "", deny(ReasonCallbackFailed)
	}

	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", deny(ReasonCallbackFailed)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cipherframe-edge")
	req.Header.Set("webhook-id", msgID)
	req.Header.Set("webhook-timestamp", strconv.FormatInt(now.Unix(), 10))
	req.Header.Set("webhook-signature", SignatureHeader(secrets, msgID, now, body))

	res, err := a.client.Do(req)
	if err != nil {
		return "", deny(ReasonCallbackFailed)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return "", deny(ReasonCallbackStatus)
	}
	raw, err := outbound.ReadAll(res.Body, MaxCallbackResponseBytes)
	if err != nil {
		return "", deny(ReasonCallbackResponse)
	}
	return a.parseAnswer(raw)
}

func (a *Authorizer) parseAnswer(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var ans callbackAnswer
	if err := dec.Decode(&ans); err != nil {
		return "", deny(ReasonCallbackResponse)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) { // trailing data
		return "", deny(ReasonCallbackResponse)
	}
	if ans.Allow == nil {
		return "", deny(ReasonCallbackResponse)
	}
	if !*ans.Allow {
		return "", deny(ReasonCallbackDenied)
	}
	if ans.ViewerID == nil || a.validateViewer(*ans.ViewerID) != nil {
		return "", deny(ReasonCallbackViewer)
	}
	return *ans.ViewerID, nil
}

func newMessageID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "msg_" + hex.EncodeToString(b), nil
}

// Signature returns one Standard Webhooks signature, "v1," followed by the base64 of the
// HMAC-SHA256 of "<id>.<unix timestamp>.<body>" under the secret.
func Signature(secret []byte, id string, ts time.Time, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(id))
	mac.Write([]byte{'.'})
	mac.Write([]byte(strconv.FormatInt(ts.Unix(), 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// SignatureHeader returns the webhook-signature header value: one signature per secret, separated
// by spaces, so a tenant that has not switched to a rotated secret yet still verifies.
func SignatureHeader(secrets [][]byte, id string, ts time.Time, body []byte) string {
	sigs := make([]string, len(secrets))
	for i, s := range secrets {
		sigs[i] = Signature(s, id, ts, body)
	}
	return strings.Join(sigs, " ")
}
