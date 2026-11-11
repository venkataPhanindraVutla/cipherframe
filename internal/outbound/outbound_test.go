package outbound

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestBlockedRanges(t *testing.T) {
	cases := map[string]bool{
		// blocked
		"127.0.0.1": true, "127.255.255.254": true, "::1": true,
		"10.0.0.1": true, "172.16.0.1": true, "172.31.255.255": true, "192.168.1.1": true,
		"fd00::1": true, "fc00::1": true,
		"169.254.169.254": true, "169.254.0.1": true, "fe80::1": true,
		"224.0.0.1": true, "239.255.255.255": true, "ff02::1": true, "ff05::2": true,
		"0.0.0.0": true, "::": true, "0.1.2.3": true,
		"100.64.0.1": true, "100.127.255.254": true,
		"::ffff:127.0.0.1": true, "::ffff:10.0.0.1": true, "::ffff:169.254.169.254": true, "::ffff:100.64.0.1": true,
		"64:ff9b::7f00:1": true, "2002:7f00:1::1": true,
		"192.0.0.1": true, "198.18.0.1": true, "240.0.0.1": true, "255.255.255.255": true,
		// allowed
		"8.8.8.8": false, "1.1.1.1": false, "172.15.255.255": false, "172.32.0.1": false,
		"100.63.255.255": false, "100.128.0.1": false, "2606:4700:4700::1111": false,
		"::ffff:8.8.8.8": false, "93.184.216.34": false,
	}
	for s, want := range cases {
		if got := blocked(netip.MustParseAddr(s), false); got != want {
			t.Errorf("blocked(%s) = %v, want %v", s, got, want)
		}
	}
	if blocked(netip.MustParseAddr("127.0.0.1"), true) || blocked(netip.MustParseAddr("::1"), true) {
		t.Error("loopback must be allowed when AllowLoopback is set")
	}
	for _, s := range []string{"10.0.0.1", "::ffff:10.0.0.1", "169.254.169.254", "fd00::1"} {
		if !blocked(netip.MustParseAddr(s), true) {
			t.Errorf("AllowLoopback must not allow %s", s)
		}
	}
}

func TestCheckURL(t *testing.T) {
	for _, u := range []string{"https://example.com/a", "https://example.com:8443/x?y=1", "https://[2606:4700:4700::1111]/"} {
		if err := CheckURL(u); err != nil {
			t.Errorf("CheckURL(%q) = %v", u, err)
		}
	}
	bad := []string{
		"http://example.com/", "ftp://example.com/", "file:///etc/passwd", "example.com", "https://", "https:///x",
		"https://user:pw@example.com/", "https://example.com/#frag", "gopher://example.com", "",
	}
	for _, u := range bad {
		if err := CheckURL(u); !errors.Is(err, ErrBadURL) {
			t.Errorf("CheckURL(%q) = %v, want ErrBadURL", u, err)
		}
	}
	blockedURLs := []string{
		"https://127.0.0.1/", "https://10.1.2.3/", "https://169.254.169.254/latest", "https://[::1]/",
		"https://[::ffff:10.0.0.1]/", "https://100.64.0.1/", "https://192.168.0.1/", "https://[fd00::1]/",
		"https://0.0.0.0/", "https://224.0.0.1/",
	}
	for _, u := range blockedURLs {
		if err := CheckURL(u); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("CheckURL(%q) = %v, want ErrBlockedAddress", u, err)
		}
	}
}

func testServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func get(t *testing.T, c *Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.Do(req)
}

// getErr is get for requests that are expected to fail or whose body is not needed.
func getErr(t *testing.T, c *Client, url string) error {
	t.Helper()
	res, err := get(t, c, url)
	if res != nil {
		_ = res.Body.Close()
	}
	return err
}

func TestLoopbackRefusedByDefault(t *testing.T) {
	var hits int
	srv, pool := testServer(t, func(w http.ResponseWriter, _ *http.Request) { hits++; _, _ = w.Write([]byte("x")) })
	c := New(Options{RootCAs: pool})
	if err := getErr(t, c, srv.URL); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("literal 127.0.0.1: err = %v, want ErrBlockedAddress", err)
	}
	// A hostname that resolves to loopback is not caught by CheckURL; the dial-time check refuses
	// it (the DNS-rebinding defence).
	host := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	if err := getErr(t, c, host); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("localhost: err = %v, want ErrBlockedAddress", err)
	}
	if hits != 0 {
		t.Fatal("the server was reached")
	}
}

func TestAllowLoopbackForTests(t *testing.T) {
	srv, pool := testServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hello")) })
	c := New(Options{AllowLoopback: true, RootCAs: pool})
	res, err := get(t, c, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, err := ReadAll(res.Body, 10)
	if err != nil || string(b) != "hello" {
		t.Fatalf("body %q err %v", b, err)
	}
}

func TestPlainHTTPRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	c := New(Options{AllowLoopback: true})
	if err := getErr(t, c, srv.URL); !errors.Is(err, ErrBadURL) {
		t.Fatalf("err = %v, want ErrBadURL", err)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var hits int
	srv, pool := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			hits++
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	c := New(Options{AllowLoopback: true, RootCAs: pool})
	if err := getErr(t, c, srv.URL+"/start"); !errors.Is(err, ErrRedirect) {
		t.Fatalf("err = %v, want ErrRedirect", err)
	}
	if hits != 0 {
		t.Fatal("the redirect target was requested")
	}
}

func TestReadAllLimit(t *testing.T) {
	if _, err := ReadAll(strings.NewReader("12345"), 4); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if b, err := ReadAll(strings.NewReader("1234"), 4); err != nil || string(b) != "1234" {
		t.Fatalf("b %q err %v", b, err)
	}
}

func TestTimeout(t *testing.T) {
	srv, pool := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
		_, _ = w.Write([]byte("late"))
	})
	c := New(Options{AllowLoopback: true, RootCAs: pool, Timeout: 200 * time.Millisecond})
	start := time.Now()
	if err := getErr(t, c, srv.URL); err == nil {
		t.Fatal("expected a timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("the timeout was not applied")
	}
}

func TestErrorsDoNotCarryTheURL(t *testing.T) {
	c := New(Options{})
	err := getErr(t, c, "https://127.0.0.1:1/secret-path?token=test-fixture-abc")
	if err == nil || strings.Contains(err.Error(), "secret-path") || strings.Contains(err.Error(), "test-fixture") {
		t.Fatalf("err = %v", err)
	}
}
