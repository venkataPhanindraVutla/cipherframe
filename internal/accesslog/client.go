package accesslog

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

// Client is what edge saw of the requester: the peer address of the connection and the
// User-Agent header, as received. It is only ever stored when the tenant allows it (see
// Recorder), and is cleaned (parsed, cut, stripped of control characters) at that point.
//
// There is no trusted-proxy setting in Cipherframe, so RemoteAddr is the address of the TCP peer.
// Behind a reverse proxy or load balancer that is the proxy's address, not the viewer's, and
// X-Forwarded-For is deliberately never read: a client can write anything in it.
type Client struct {
	RemoteAddr string
	UserAgent  string
}

type clientKey struct{}

// WithClient returns a context carrying c.
func WithClient(ctx context.Context, c Client) context.Context {
	return context.WithValue(ctx, clientKey{}, c)
}

// ClientFrom returns the client stored by Middleware (the zero Client when there is none).
func ClientFrom(ctx context.Context) Client {
	c, _ := ctx.Value(clientKey{}).(Client)
	return c
}

// Middleware stores the request's peer address and User-Agent in its context, for handlers that
// record access events. It copies two strings and reads nothing else.
func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(WithClient(r.Context(), Client{
				RemoteAddr: r.RemoteAddr, UserAgent: r.UserAgent(),
			})))
		})
	}
}

// cleanIP returns the peer address as text without port, mapped IPv4 unwrapped, or "" when it does
// not parse.
func cleanIP(remote string) string {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return ap.Addr().Unmap().WithZone("").String()
	}
	if a, err := netip.ParseAddr(remote); err == nil {
		return a.Unmap().WithZone("").String()
	}
	return ""
}

// cleanUserAgent makes a User-Agent safe to store: valid UTF-8, no control characters (Postgres
// text also refuses NUL), at most db.MaxAccessUserAgentChars characters.
func cleanUserAgent(ua string) string {
	if ua == "" {
		return ""
	}
	if !utf8.ValidString(ua) {
		ua = strings.ToValidUTF8(ua, "")
	}
	var b strings.Builder
	n := 0
	for _, r := range ua {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			continue
		}
		if n == db.MaxAccessUserAgentChars {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}
