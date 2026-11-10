package db

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// mapError turns a driver error into an *errs.Error (ADR 0012). The original error stays
// reachable as the cause and is never part of the client-facing detail.
//
//	no rows                                  -> not_found
//	unique violation                         -> conflict
//	deadline, statement timeout, net timeout -> timeout
//	connection loss, shutdown, deadlock,
//	serialization failure, closed pool       -> dependency_unavailable
//	anything else                            -> internal_error (never not_found)
func mapError(err error) error {
	if err == nil {
		return nil
	}
	var already *errs.Error
	if errors.As(err, &already) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.Wrap(errs.NotFound, "resource not found", err)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return mapPgError(pgErr, err)
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), pgconn.Timeout(err):
		return errs.Wrap(errs.Timeout, "database operation timed out", err)
	case isConnectionError(err):
		return errs.Wrap(errs.DependencyUnavailable, "database unavailable", err)
	}
	return errs.Wrap(errs.InternalError, "database error", err)
}

func mapPgError(pgErr *pgconn.PgError, err error) error {
	code := pgErr.Code
	switch {
	case code == "23505": // unique_violation
		return errs.Wrap(errs.Conflict, "resource already exists", err)
	case code == "57014": // query_canceled (statement timeout)
		return errs.Wrap(errs.Timeout, "database operation timed out", err)
	case code == "40001", code == "40P01": // serialization_failure, deadlock_detected
		return errs.Wrap(errs.DependencyUnavailable, "database busy, retry", err)
	case strings.HasPrefix(code, "08"), // connection exception
		strings.HasPrefix(code, "53"),                     // insufficient resources
		code == "57P01", code == "57P02", code == "57P03", // shutdown, crash, cannot connect now
		code == "25006": // read_only_sql_transaction (failover to a replica)
		return errs.Wrap(errs.DependencyUnavailable, "database unavailable", err)
	}
	return errs.Wrap(errs.InternalError, "database error", err)
}

func isConnectionError(err error) bool {
	var connErr *pgconn.ConnectError
	if errors.As(err, &connErr) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// A closed pool (puddle) and a closed connection (pgconn) report these messages.
	msg := err.Error()
	return strings.Contains(msg, "closed pool") || strings.Contains(msg, "conn closed")
}
