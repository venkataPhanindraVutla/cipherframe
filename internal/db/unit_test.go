package db

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

func TestMapError(t *testing.T) {
	t.Parallel()
	own := errs.New(errs.Forbidden, "nope")
	tests := []struct {
		name string
		err  error
		want errs.Code
	}{
		{"no rows", pgx.ErrNoRows, errs.NotFound},
		{"wrapped no rows", fmt.Errorf("scan: %w", pgx.ErrNoRows), errs.NotFound},
		{"unique violation", &pgconn.PgError{Code: "23505"}, errs.Conflict},
		{"foreign key violation is not not_found", &pgconn.PgError{Code: "23503"}, errs.InternalError},
		{"check violation", &pgconn.PgError{Code: "23514"}, errs.InternalError},
		{"statement timeout", &pgconn.PgError{Code: "57014"}, errs.Timeout},
		{"deadlock", &pgconn.PgError{Code: "40P01"}, errs.DependencyUnavailable},
		{"serialization", &pgconn.PgError{Code: "40001"}, errs.DependencyUnavailable},
		{"connection failure", &pgconn.PgError{Code: "08006"}, errs.DependencyUnavailable},
		{"admin shutdown", &pgconn.PgError{Code: "57P01"}, errs.DependencyUnavailable},
		{"too many connections", &pgconn.PgError{Code: "53300"}, errs.DependencyUnavailable},
		{"deadline", context.DeadlineExceeded, errs.Timeout},
		{"wrapped deadline", fmt.Errorf("query: %w", context.DeadlineExceeded), errs.Timeout},
		{"canceled", context.Canceled, errs.Timeout},
		{"net error", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, errs.DependencyUnavailable},
		{"eof", io.EOF, errs.DependencyUnavailable},
		{"unexpected eof", io.ErrUnexpectedEOF, errs.DependencyUnavailable},
		{"closed pool", errors.New("closed pool"), errs.DependencyUnavailable},
		{"unknown", errors.New("boom"), errs.InternalError},
		{"unknown pg error", &pgconn.PgError{Code: "XX000"}, errs.InternalError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mapError(tt.err)
			var e *errs.Error
			if !errors.As(got, &e) {
				t.Fatalf("mapError(%v) = %T, want *errs.Error", tt.err, got)
			}
			if e.Code != tt.want {
				t.Fatalf("code = %s, want %s", e.Code, tt.want)
			}
			if !errors.Is(got, tt.err) {
				t.Fatal("cause not reachable through errors.Is")
			}
			if tt.want != errs.NotFound && e.Code == errs.NotFound {
				t.Fatal("non-no-rows error became not_found")
			}
		})
	}

	if mapError(nil) != nil {
		t.Fatal("mapError(nil) must be nil")
	}
	if got := mapError(own); !errors.Is(got, own) {
		t.Fatal("an *errs.Error must pass through unchanged")
	}
}

func TestMapErrorDetailHidesCause(t *testing.T) {
	t.Parallel()
	got := mapError(&pgconn.PgError{Code: "XX000", Message: "secret internals", Detail: "row (1,2)"})
	var e *errs.Error
	if !errors.As(got, &e) {
		t.Fatal("not an errs.Error")
	}
	if strings.Contains(e.Error(), "secret") || strings.Contains(e.Detail, "secret") {
		t.Fatalf("cause text leaked: %q", e.Error())
	}
}

func TestIDConversion(t *testing.T) {
	t.Parallel()
	tid := id.New[id.TenantKind]()
	pg := toPG(tid)
	if !pg.Valid {
		t.Fatal("valid ID must be a valid UUID")
	}
	if back := fromPG[id.TenantKind](pg); back != tid {
		t.Fatalf("round trip: got %v, want %v", back, tid)
	}
	if uuid.UUID(pg.Bytes) != tid.UUID() {
		t.Fatal("bytes differ")
	}

	var zero id.TenantID
	if toPG(zero).Valid {
		t.Fatal("zero ID must convert to NULL")
	}
	if !fromPG[id.ClientKind](toPG(id.ClientID{})).IsZero() {
		t.Fatal("NULL must convert to the zero ID")
	}

	_, err := requirePG(zero)
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != errs.InvalidRequest {
		t.Fatalf("requirePG(zero) = %v, want invalid_request", err)
	}
}

func TestParseMajorAndVersionCheck(t *testing.T) {
	t.Parallel()
	tests := []struct {
		version string
		ok      bool
	}{
		{"15.x", false},
		{"15.4", false},
		{"9.6.24", false},
		{"16.0", true},
		{"16.15", true},
		{"16.15 (Debian 16.15-1.pgdg120+1)", true},
		{"17.11", true},
		{"18.6 (Debian 18.6-1.pgdg13+1)", true},
		{"18beta1", true},
		{"", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		err := checkVersion(tt.version)
		if (err == nil) != tt.ok {
			t.Errorf("checkVersion(%q) = %v, want ok=%v", tt.version, err, tt.ok)
		}
		if err != nil && !errors.Is(err, ErrUnsupportedServer) {
			t.Errorf("checkVersion(%q) error does not wrap ErrUnsupportedServer", tt.version)
		}
	}
}

func TestOpenErrorsDoNotContainURL(t *testing.T) {
	t.Parallel()
	const secretPass = "hunter2-very-secret"
	urls := []string{
		// Parse failure.
		"postgres://user:" + secretPass + "@host:notaport/db",
		// Connect failure: nothing listens on port 1.
		"postgres://user:" + secretPass + "@127.0.0.1:1/db?connect_timeout=1",
	}
	for _, u := range urls {
		cfg := &config.Config{DatabaseURL: config.NewSecret(u)}
		ctx, cancel := context.WithTimeout(context.Background(), 5e9)
		pool, err := Open(ctx, cfg)
		cancel()
		if err == nil {
			pool.Close()
			t.Fatal("expected an error")
		}
		var causeText string
		for e := err; e != nil; e = errors.Unwrap(e) {
			causeText += e.Error() + "|"
		}
		for _, bad := range []string{secretPass, "user", "127.0.0.1", "postgres://"} {
			if strings.Contains(causeText, bad) {
				t.Fatalf("error chain contains %q: %s", bad, causeText)
			}
		}
	}
}

func TestOpenRejectsMissingURL(t *testing.T) {
	t.Parallel()
	if _, err := Open(context.Background(), &config.Config{}); err == nil {
		t.Fatal("expected error for empty URL")
	}
	if _, err := Open(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestScopeAndStateValidity(t *testing.T) {
	t.Parallel()
	if !ScopeAdmin.Valid() || Scope("root").Valid() || Scope("").Valid() {
		t.Fatal("scope validity wrong")
	}
	if !AssetReady.Valid() || AssetState("bogus").Valid() {
		t.Fatal("state validity wrong")
	}
}

func TestRepoInputValidationWithoutDatabase(t *testing.T) {
	t.Parallel()
	r := &Repos{} // validation fails before any query, so a nil queries value is never used
	ctx := context.Background()
	tid := id.New[id.TenantKind]()
	cid := id.New[id.ClientKind]()

	check := func(name string, err error, want errs.Code) {
		t.Helper()
		var e *errs.Error
		if !errors.As(err, &e) || e.Code != want {
			t.Errorf("%s: got %v, want %s", name, err, want)
		}
	}
	_, err := r.GetTenant(ctx, id.TenantID{})
	check("zero tenant", err, errs.InvalidRequest)
	_, err = r.CreateAPIKey(ctx, NewAPIKey{ClientID: cid, Scopes: []Scope{"root"}})
	check("bad scope", err, errs.InvalidRequest)
	_, err = r.CreateAsset(ctx, tid, cid, "bogus")
	check("bad state", err, errs.InvalidRequest)
	_, err = r.ListClients(ctx, tid, 0, 0)
	check("bad page", err, errs.InvalidRequest)
	_, err = r.ListAuditEvents(ctx, tid, nil, maxPage+1)
	check("bad audit page", err, errs.InvalidRequest)
	_, err = r.InsertAuditEvent(ctx, NewAuditEvent{TenantID: tid})
	check("missing action", err, errs.InvalidRequest)
}
