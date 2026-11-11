// Package outbound is the HTTP client for requests that Cipherframe makes to a tenant's own
// servers: fetching a JWKS document and calling a playback-authorization callback (ADR 0029,
// 0031). The URLs are chosen by a tenant, so the client is an SSRF guard as much as a client:
//
//   - https only: a request to any other scheme is refused before a socket is opened;
//   - the address that is actually dialed is checked, after DNS resolution and for every
//     connection attempt, so a hostname that resolves to a private address (and a DNS answer that
//     changes between a check and a dial) cannot reach an internal service;
//   - loopback, private (RFC 1918 and ULA), link-local (including cloud metadata addresses),
//     multicast, unspecified, CGNAT (100.64.0.0/10), and the other special-purpose ranges are
//     refused, in plain form and in IPv4-mapped, NAT64 and 6to4 forms;
//   - redirects are never followed (a redirect would move the request to a target nobody
//     validated);
//   - proxies from the environment are ignored;
//   - the response body is read through ReadAll with a size limit, and a whole request has a
//     deadline.
//
// Nothing here logs. Errors name the failure class, never the URL, a header or a body.
package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// Errors returned by the client. They carry no URL, address or response content.
var (
	// ErrBlockedAddress means the destination resolved to an address the guard refuses.
	ErrBlockedAddress = errors.New("outbound: the destination address is not allowed")
	// ErrBadURL means the URL is not an acceptable https URL.
	ErrBadURL = errors.New("outbound: the URL must be an absolute https URL without credentials")
	// ErrRedirect means the server answered with a redirect, which is never followed.
	ErrRedirect = errors.New("outbound: redirects are not followed")
	// ErrTooLarge means the response body exceeded the limit.
	ErrTooLarge = errors.New("outbound: the response is too large")
)

// Options configure a Client. The zero value is the production configuration.
type Options struct {
	// Timeout bounds a whole request, including the dial, the TLS handshake and reading the
	// response. Default 5 seconds.
	Timeout time.Duration
	// AllowLoopback lets the client reach loopback addresses. It exists for tests that run a TLS
	// server on 127.0.0.1 and must never be set in production code. Every other range stays
	// blocked.
	AllowLoopback bool
	// RootCAs replaces the system roots. Tests use it to trust a test server's certificate.
	RootCAs *x509.CertPool
}

// Client is an SSRF-guarded HTTP client. Safe for concurrent use.
type Client struct {
	hc            *http.Client
	allowLoopback bool
}

// New builds a Client.
func New(o Options) *Client {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	d := &net.Dialer{
		Timeout: o.Timeout,
		// Control runs for every connection attempt, with the numeric address about to be dialed:
		// this is the check that DNS rebinding cannot get around.
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return ErrBlockedAddress
			}
			if blocked(ap.Addr(), o.AllowLoopback) {
				return ErrBlockedAddress
			}
			return nil
		},
	}
	tr := &http.Transport{
		Proxy:                 nil, // never use HTTP(S)_PROXY: a proxy would dial on our behalf, unchecked
		DialContext:           d.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs},
		TLSHandshakeTimeout:   o.Timeout,
		ResponseHeaderTimeout: o.Timeout,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Client{
		allowLoopback: o.AllowLoopback,
		hc: &http.Client{
			Transport:     tr,
			Timeout:       o.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect },
		},
	}
}

// CheckURL reports whether raw is an acceptable target: an absolute https URL with a host, no
// user information and no fragment. An IP literal in a blocked range is refused here too, for a
// clear error at configuration time; the dial-time check is the authority.
func CheckURL(raw string) error {
	return checkURL(raw, false)
}

func checkURL(raw string, allowLoopback bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return ErrBadURL
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && blocked(ip, allowLoopback) {
		return ErrBlockedAddress
	}
	return nil
}

// Do sends req and returns the response. The URL must pass CheckURL. A redirect is an error. The
// caller must close the body, and should read it with ReadAll.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := checkURL(req.URL.String(), c.allowLoopback); err != nil {
		return nil, err
	}
	res, err := c.hc.Do(req)
	if err != nil {
		// net/http wraps the error in a *url.Error that holds the URL. Strip it.
		return nil, sanitize(err)
	}
	return res, nil
}

// sanitize reduces a transport error to a message without the URL.
func sanitize(err error) error {
	switch {
	case errors.Is(err, ErrBlockedAddress):
		return ErrBlockedAddress
	case errors.Is(err, ErrRedirect):
		return ErrRedirect
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		return context.Canceled
	}
	return errors.New("outbound: the request failed")
}

// ReadAll reads at most max bytes of r. A longer body is ErrTooLarge. It does not close r.
func ReadAll(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, errors.New("outbound: reading the response failed")
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}

// specialPrefixes are the ranges netip's predicates do not cover.
var specialPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this network"
	"100.64.0.0/10",   // carrier-grade NAT
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"240.0.0.0/4",     // reserved, and the broadcast address
	"64:ff9b::/96",    // NAT64: embeds an IPv4 address
	"64:ff9b:1::/48",  // local-use NAT64
	"100::/64",        // discard-only
	"2001:db8::/32",   // documentation
	"2002::/16",       // 6to4: embeds an IPv4 address
	"2001::/32",       // Teredo
	"fec0::/10",       // deprecated site-local
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// blocked reports whether a connection to ip must be refused.
func blocked(ip netip.Addr, allowLoopback bool) bool {
	ip = ip.WithZone("")
	// An IPv4-mapped IPv6 address (::ffff:10.0.0.1) is judged as the IPv4 address it carries.
	ip = ip.Unmap()
	if !ip.IsValid() {
		return true
	}
	if ip.IsLoopback() {
		return !allowLoopback
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, p := range specialPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
