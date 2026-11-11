// Package vault is the Vault Transit key provider (M2-2, ADR 0021, ADR 0022). It wraps content
// keys with a Transit key held by HashiCorp Vault or OpenBao, so the KEK never leaves the server.
//
// It speaks the Transit HTTP API with net/http and encoding/json and pulls in no SDK. The Transit
// key must be an AEAD type (aes256-gcm96, aes128-gcm96 or chacha20-poly1305): the associated data
// that binds a wrapped key to its asset is sent as Transit's associated_data, and a key type that
// cannot authenticate it is refused on first use.
//
// Server responses are never copied into errors, because Vault can echo request input. An error
// carries the operation, the HTTP status and a fixed category only.
package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

// Name is the provider name recorded in every wrapped key.
const Name = "vault"

// maxBody bounds how much of a response is read.
const maxBody = 1 << 20

// aeadTypes are the Transit key types that authenticate associated data.
var aeadTypes = map[string]bool{
	"aes256-gcm96":      true,
	"aes128-gcm96":      true,
	"chacha20-poly1305": true,
}

// Provider is the Vault Transit key provider. It is safe for concurrent use. Every printed form
// hides the token.
type Provider struct {
	client    *http.Client
	token     config.Secret
	addr      string
	mount     string
	keyName   string
	namespace string
	base      string // addr + "/v1/" + mount

	mu       sync.Mutex
	verified bool // the key type has been checked and is an AEAD type
}

// New builds the provider from configuration. It reads the CA file, if any, and makes no network
// call: the key is first contacted on first use.
func New(cfg config.KMSVault, log *slog.Logger) (*Provider, error) {
	if cfg.Addr == "" || cfg.KeyName == "" || cfg.Token.IsEmpty() {
		return nil, errors.New("vault key provider: address, token and key name are required")
	}
	if cfg.TransitMount == "" {
		cfg.TransitMount = config.DefaultVaultTransitMount
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = config.DefaultVaultTimeout
	}
	u, err := url.Parse(cfg.Addr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("vault key provider: the address must be an absolute http or https URL")
	}

	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("vault key provider: no default transport")
	}
	tr = tr.Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, errors.New("vault key provider: cannot read the CA file")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("vault key provider: the CA file holds no PEM certificate")
		}
		tr.TLSClientConfig.RootCAs = pool
	}

	p := &Provider{
		client: &http.Client{
			Transport: tr,
			Timeout:   cfg.Timeout,
			// A redirect would resend the token to whatever host answered. Never follow one.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		token:     cfg.Token,
		addr:      strings.TrimRight(cfg.Addr, "/"),
		mount:     cfg.TransitMount,
		keyName:   cfg.KeyName,
		namespace: cfg.Namespace,
	}
	p.base = p.addr + "/v1/" + p.mount
	if log != nil {
		log.Info("vault transit key provider configured",
			slog.String("provider", Name), slog.String("addr", p.addr),
			slog.String("transit_mount", p.mount), slog.String("key_name", p.keyName),
			slog.String("namespace", p.namespace))
	}
	return p, nil
}

// Name implements kms.Provider.
func (*Provider) Name() string { return Name }

// Current implements kms.Provider. It reads the key's latest version from the server.
func (p *Provider) Current(ctx context.Context) (kms.KeyRef, error) {
	info, err := p.readKey(ctx, "current")
	if err != nil {
		return kms.KeyRef{}, err
	}
	return kms.KeyRef{KeyID: p.keyName, Version: strconv.Itoa(info.latest)}, nil
}

// Wrap implements kms.Provider. The result carries the version Vault actually used, parsed from the
// ciphertext prefix, so a rotation between Current and Wrap is visible to the caller.
func (p *Provider) Wrap(ctx context.Context, plaintext, aad []byte) (kms.Wrapped, error) {
	const op = "wrap"
	if err := kms.FromContext(ctx, Name, op); err != nil {
		return kms.Wrapped{}, err
	}
	if len(plaintext) == 0 {
		return kms.Wrapped{}, kms.New(kms.Invalid, Name, op, "plaintext is empty")
	}
	if len(aad) == 0 {
		return kms.Wrapped{}, kms.New(kms.Invalid, Name, op, "associated data is empty")
	}
	if err := p.ensureVerified(ctx, op); err != nil {
		return kms.Wrapped{}, err
	}
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := p.do(ctx, op, http.MethodPost, "/encrypt/"+url.PathEscape(p.keyName), map[string]string{
		"plaintext":       base64.StdEncoding.EncodeToString(plaintext),
		"associated_data": base64.StdEncoding.EncodeToString(aad),
	}, &out)
	if err != nil {
		return kms.Wrapped{}, err
	}
	version, _, ok := parseCiphertext(out.Data.Ciphertext)
	if !ok {
		return kms.Wrapped{}, kms.New(kms.Other, Name, op, "the server returned an unexpected ciphertext format")
	}
	return kms.Wrapped{
		Provider:   Name,
		KeyID:      p.keyName,
		Version:    strconv.Itoa(version),
		Ciphertext: []byte(out.Data.Ciphertext),
	}, nil
}

// Unwrap implements kms.Provider. It never returns partial plaintext: on any failure the result is
// nil.
func (p *Provider) Unwrap(ctx context.Context, w kms.Wrapped, aad []byte) ([]byte, error) {
	const op = "unwrap"
	if err := kms.FromContext(ctx, Name, op); err != nil {
		return nil, err
	}
	if w.Provider != Name {
		return nil, kms.New(kms.Invalid, Name, op, "the key was not wrapped by this provider")
	}
	if w.KeyID != p.keyName {
		return nil, kms.New(kms.NotConfigured, Name, op, "unknown KEK id")
	}
	version, err := strconv.Atoi(w.Version)
	if err != nil || version < 1 {
		return nil, kms.New(kms.Invalid, Name, op, "malformed KEK version")
	}
	if len(aad) == 0 {
		return nil, kms.New(kms.Invalid, Name, op, "associated data is empty")
	}
	ct := string(w.Ciphertext)
	prefixVersion, _, ok := parseCiphertext(ct)
	if !ok || prefixVersion != version {
		return nil, kms.New(kms.Invalid, Name, op, "malformed wrapped key")
	}
	if err := p.ensureVerified(ctx, op); err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	err = p.do(ctx, op, http.MethodPost, "/decrypt/"+url.PathEscape(p.keyName), map[string]string{
		"ciphertext":      ct,
		"associated_data": base64.StdEncoding.EncodeToString(aad),
	}, &out)
	if err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil || len(pt) == 0 {
		return nil, kms.New(kms.Other, Name, op, "the server returned an unexpected plaintext format")
	}
	return pt, nil
}

// parseCiphertext splits "vault:vN:<base64>" into N and the payload. It accepts only canonical
// standard base64. A lenient decoder (Go's default) ignores the unused trailing bits of the last
// character, so without this check a one-bit change there could still unwrap and the ciphertext
// would be malleable.
func parseCiphertext(s string) (version int, payload string, ok bool) {
	rest, found := strings.CutPrefix(s, "vault:v")
	if !found {
		return 0, "", false
	}
	num, payload, found := strings.Cut(rest, ":")
	if !found || num == "" || payload == "" || (num[0] == '0') {
		return 0, "", false
	}
	for _, r := range num {
		if r < '0' || r > '9' {
			return 0, "", false
		}
	}
	version, err := strconv.Atoi(num)
	if err != nil || version < 1 {
		return 0, "", false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != payload {
		return 0, "", false
	}
	return version, payload, true
}

type keyInfo struct {
	keyType string
	latest  int
}

// readKey reads the key's metadata (no key material is in the response, and none is kept) and
// verifies that its type authenticates associated data.
func (p *Provider) readKey(ctx context.Context, op string) (keyInfo, error) {
	if err := kms.FromContext(ctx, Name, op); err != nil {
		return keyInfo{}, err
	}
	var out struct {
		Data struct {
			Type          string `json:"type"`
			LatestVersion int    `json:"latest_version"`
		} `json:"data"`
	}
	if err := p.do(ctx, op, http.MethodGet, "/keys/"+url.PathEscape(p.keyName), nil, &out); err != nil {
		return keyInfo{}, err
	}
	if !aeadTypes[out.Data.Type] {
		return keyInfo{}, kms.New(kms.NotConfigured, Name, op,
			"the Transit key type cannot authenticate associated data; use aes256-gcm96")
	}
	if out.Data.LatestVersion < 1 {
		return keyInfo{}, kms.New(kms.Other, Name, op, "the server returned an unexpected key version")
	}
	p.mu.Lock()
	p.verified = true
	p.mu.Unlock()
	return keyInfo{keyType: out.Data.Type, latest: out.Data.LatestVersion}, nil
}

// ensureVerified checks the key type on first use. A failure is not cached, so a key fixed on the
// server is picked up without a restart.
func (p *Provider) ensureVerified(ctx context.Context, op string) error {
	p.mu.Lock()
	ok := p.verified
	p.mu.Unlock()
	if ok {
		return nil
	}
	_, err := p.readKey(ctx, op)
	return err
}

// do sends one request and decodes a 2xx JSON response into out. Every failure is a *kms.Error.
func (p *Provider) do(ctx context.Context, op, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return kms.New(kms.Other, Name, op, "cannot encode the request")
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, body)
	if err != nil {
		return kms.New(kms.Other, Name, op, "cannot build the request")
	}
	req.Header.Set("X-Vault-Token", p.token.Reveal())
	req.Header.Set("X-Vault-Request", "true")
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.namespace)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		// err can quote the URL but never a header or body; it is not kept either way.
		if e := kms.FromContext(ctx, Name, op); e != nil {
			return e
		}
		return kms.New(kms.Unavailable, Name, op, "the Transit server could not be reached")
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		if e := kms.FromContext(ctx, Name, op); e != nil {
			return e
		}
		return kms.New(kms.Unavailable, Name, op, "the Transit server did not finish its response")
	}
	if len(raw) > maxBody {
		return kms.New(kms.Other, Name, op, "the server response is too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return classify(op, resp.StatusCode, errorMessages(raw))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return kms.New(kms.Other, Name, op, "the server returned a malformed response")
		}
	}
	return nil
}

// errorMessages extracts Vault's error strings, lower-cased, for classification only. The text is
// never stored in an error.
func errorMessages(raw []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return ""
	}
	return strings.ToLower(strings.Join(e.Errors, "; "))
}

// classify maps a non-2xx response to a typed error. msg is Vault's error text, lower-cased; it
// selects a category and is then dropped.
func classify(op string, status int, msg string) *kms.Error {
	mk := func(k kms.Kind, category string) *kms.Error {
		return kms.New(k, Name, op, fmt.Sprintf("the Transit server answered %d: %s", status, category))
	}
	switch {
	case status >= 300 && status <= 399:
		return mk(kms.Unavailable, "unexpected redirect")
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return mk(kms.Denied, "permission denied")
	case status == http.StatusNotFound:
		return mk(kms.NotConfigured, "Transit key or mount not found")
	case status == http.StatusTooManyRequests || status >= 500:
		return mk(kms.Unavailable, "server unavailable")
	case status == http.StatusBadRequest:
		switch {
		case strings.Contains(msg, "key not found"):
			return mk(kms.NotConfigured, "key not found")
		case strings.Contains(msg, "too old") || strings.Contains(msg, "too new") ||
			strings.Contains(msg, "disallowed by policy"):
			return mk(kms.NotConfigured, "key version not available")
		case op == "unwrap" && (strings.Contains(msg, "authentication failed") ||
			strings.Contains(msg, "invalid ciphertext")):
			return mk(kms.Invalid, "authentication failed")
		}
	}
	return mk(kms.Other, "unexpected response")
}

// String implements fmt.Stringer. It shows where the key is, never the token.
func (p *Provider) String() string {
	return fmt.Sprintf("vault-key-provider(addr=%s mount=%s key=%s namespace=%s token=%s)",
		p.addr, p.mount, p.keyName, p.namespace, config.Redacted)
}

// GoString implements fmt.GoStringer.
func (p *Provider) GoString() string { return p.String() }

// Format implements fmt.Formatter and covers every verb.
func (p *Provider) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(p.String())) }

// MarshalJSON implements json.Marshaler.
func (*Provider) MarshalJSON() ([]byte, error) { return []byte(`"` + config.Redacted + `"`), nil }

// LogValue implements slog.LogValuer. It shows addr, mount, key name and namespace only.
func (p *Provider) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("addr", p.addr),
		slog.String("transit_mount", p.mount),
		slog.String("key_name", p.keyName),
		slog.String("namespace", p.namespace),
	)
}

var _ kms.Provider = (*Provider)(nil)
