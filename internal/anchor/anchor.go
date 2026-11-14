// Package anchor is the optional RFC 3161 anchoring of integrity manifests (ADR 0041, M5-5).
//
// A manifest.anchor job is enqueued in the transaction that stores a manifest. The job asks the
// configured time-stamping authority for a token over SHA-256 of the manifest payload, outside any
// transaction, checks the response, and stores the token only while the manifest still has the
// payload it stamped. A failure retries with backoff; after the last attempt the manifest stays
// unanchored. Anchoring never blocks or fails an asset, and only a digest leaves the process.
package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/timestamp"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
)

// Kind is the job kind. Do not rename it once jobs of that kind exist.
const Kind = "manifest.anchor"

// MaxAttempts is the attempt limit; with the default backoff the retries span about two hours.
const MaxAttempts = 10

// maxResponseBytes bounds what is read from the authority.
const maxResponseBytes = 1 << 20

// Args are the arguments of the job: identifiers and the payload digest it is about. The digest
// lets a job notice that the manifest was re-signed since (the newer manifest has its own job).
type Args struct {
	TenantID      id.TenantID `json:"tenant_id"`
	AssetID       id.AssetID  `json:"asset_id"`
	PayloadSHA256 string      `json:"payload_sha256"` // hex
}

// Kind implements jobs.Args.
func (Args) Kind() string { return Kind }

// Enqueuer is the part of jobs.Queue that inserts a job in a transaction.
type Enqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, args jobs.Args, opts *jobs.EnqueueOpts) (int64, error)
}

// Enqueue inserts the anchor job for the manifest payload with digest payloadSHA256, in tx.
func Enqueue(ctx context.Context, q Enqueuer, tx pgx.Tx, tenant id.TenantID, asset id.AssetID, payloadSHA256 []byte) error {
	_, err := q.Enqueue(ctx, tx, Args{TenantID: tenant, AssetID: asset, PayloadSHA256: hex.EncodeToString(payloadSHA256)}, nil)
	return err
}

// Declare tells a process that only inserts jobs the kind's settings.
func Declare(reg *jobs.Registry) error {
	return jobs.Declare[Args](reg, jobs.KindConfig{MaxAttempts: MaxAttempts})
}

// Stamper obtains a verified timestamp token for a digest.
type Stamper interface {
	Stamp(ctx context.Context, digest [sha256.Size]byte) (*timestamp.Token, error)
}

// Repo is the database access the job needs. *db.Repos implements it.
type Repo interface {
	GetManifest(ctx context.Context, asset id.AssetID) (db.AssetManifest, error)
	SetManifestTimestamp(ctx context.Context, asset id.AssetID, payloadSHA256 []byte, ts db.ManifestTimestamp) (bool, error)
}

// Deps are the collaborators of the job.
type Deps struct {
	Repo    Repo
	Stamper Stamper
	// TSAURL is stored with the token.
	TSAURL string
	// Timeout is the Stamper's per-request limit; the job's own limit is a little more.
	Timeout time.Duration
	// Backoff overrides jobs.DefaultBackoff (tests).
	Backoff jobs.BackoffFunc
	Log     *slog.Logger
}

// Register registers the manifest.anchor handler on the default queue.
func Register(reg *jobs.Registry, d Deps) error {
	if d.Repo == nil || d.Stamper == nil || d.TSAURL == "" || d.Timeout <= 0 {
		return errors.New("anchor: repository, stamper, authority URL and timeout are required")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return jobs.Register(reg, d.handle, jobs.KindConfig{
		MaxAttempts: MaxAttempts, Backoff: d.Backoff, Timeout: d.Timeout + 30*time.Second,
	})
}

func (d Deps) handle(ctx context.Context, job jobs.Job[Args]) error {
	log := d.Log.With(slog.String("job", Kind), slog.String("tenant_id", job.Args.TenantID.String()),
		slog.String("asset_id", job.Args.AssetID.String()), slog.Int("attempt", job.Attempt))
	if job.Args.TenantID.IsZero() || job.Args.AssetID.IsZero() {
		return jobs.Cancel(errs.New(errs.InvalidRequest, "the job has no asset"))
	}
	m, err := d.Repo.GetManifest(ctx, job.Args.AssetID)
	switch {
	case isNotFound(err):
		return nil // the asset or its manifest is gone: nothing to anchor
	case err != nil:
		return err
	case hex.EncodeToString(m.PayloadSHA256) != job.Args.PayloadSHA256:
		return nil // re-signed since; the newer manifest has its own job
	case m.Timestamp != nil:
		return nil // already anchored (a retry after the store succeeded)
	}
	env, err := dsse.Decode(m.Envelope)
	if err != nil {
		return jobs.Cancel(errs.New(errs.InternalError, "the stored manifest does not decode"))
	}
	digest := timestamp.Digest(env.Payload)
	if !bytes.Equal(digest[:], m.PayloadSHA256) {
		return jobs.Cancel(errs.New(errs.InternalError, "the stored manifest does not match its payload digest"))
	}

	tok, err := d.Stamper.Stamp(ctx, digest) // no transaction is open here
	if err != nil {
		if job.Attempt >= job.MaxAttempts {
			log.ErrorContext(ctx, "anchoring gave up; the manifest stays unanchored", slog.String("error", err.Error()))
		} else {
			log.WarnContext(ctx, "anchoring failed; will retry", slog.String("error", err.Error()))
		}
		return err
	}
	stored, err := d.Repo.SetManifestTimestamp(ctx, job.Args.AssetID, m.PayloadSHA256, db.ManifestTimestamp{
		Token: tok.DER, GenTime: tok.GenTime, TSAURL: d.TSAURL,
	})
	if err != nil {
		return err
	}
	if !stored {
		log.InfoContext(ctx, "the manifest changed while it was being stamped; the token was dropped")
		return nil
	}
	log.InfoContext(ctx, "manifest anchored", slog.Time("gen_time", tok.GenTime))
	return nil
}

func isNotFound(err error) bool {
	var e *errs.Error
	return errors.As(err, &e) && e.Code == errs.NotFound
}

// Client asks one time-stamping authority for tokens over HTTP (RFC 3161 section 3.4). The URL is
// the operator's own setting, not a tenant's, so unlike package outbound it may point at a private
// address; it is https unless the operator runs a local authority in development.
type Client struct {
	URL string
	// Policy is the requested policy OID in dotted decimal; empty asks for none.
	Policy string
	HTTP   *http.Client
}

// NewClient returns a Client with a request limit of timeout and no redirects.
func NewClient(url, policy string, timeout time.Duration) *Client {
	return &Client{URL: url, Policy: policy, HTTP: &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Stamp implements Stamper.
func (c *Client) Stamp(ctx context.Context, digest [sha256.Size]byte) (*timestamp.Token, error) {
	nonce, err := timestamp.NewNonce()
	if err != nil {
		return nil, err
	}
	policy, err := parseOID(c.Policy)
	if err != nil {
		return nil, err
	}
	body, err := timestamp.BuildRequest(digest, nonce, policy)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("anchor: bad authority URL")
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anchor: request to the authority failed: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anchor: the authority answered HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("anchor: read the authority's answer: %w", err)
	}
	if len(data) > maxResponseBytes {
		return nil, errors.New("anchor: the authority's answer is too large")
	}
	return timestamp.ParseResponse(data, digest, nonce)
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, errors.New("anchor: bad policy OID")
		}
		oid[i] = n
	}
	return oid, nil
}
