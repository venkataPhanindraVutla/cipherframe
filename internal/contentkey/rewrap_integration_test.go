//go:build integration

package contentkey_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/vault"
)

// manager returns a Manager on the same database as e with another provider set, as a process
// started after a configuration change would have.
func (e *env) manager(t *testing.T, current kms.Provider, others ...kms.Provider) *contentkey.Manager {
	t.Helper()
	reg, err := kms.NewRegistry(current, others...)
	if err != nil {
		t.Fatal(err)
	}
	return contentkey.NewManager(e.pool, reg, newLogger(e.logs))
}

// createN creates n assets with a content key each, through mgr, and returns the keys by asset.
func (e *env) createN(t *testing.T, mgr *contentkey.Manager, n int) map[id.AssetID][]byte {
	t.Helper()
	ctx := context.Background()
	out := map[id.AssetID][]byte{}
	for range n {
		asset := e.newAsset(t, e.tenant, e.client)
		var k contentkey.ContentKey
		err := db.Tx(ctx, e.pool, func(tx *db.Repos) error {
			var err error
			k, err = mgr.Create(ctx, tx, e.tenant.ID, asset)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		out[asset] = k.Bytes()
	}
	return out
}

// startWorker runs a queue that works kms.rewrap jobs through mgr. It stops with the test.
func (e *env) startWorker(t *testing.T, mgr *contentkey.Manager, cfg jobs.KindConfig) *jobs.Queue {
	t.Helper()
	reg := jobs.NewRegistry()
	inserter, err := jobs.NewQueue(e.pool, reg, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := contentkey.RegisterRewrapJob(reg, mgr, inserter, cfg); err != nil {
		t.Fatal(err)
	}
	q, err := jobs.NewQueue(e.pool, reg, jobs.Config{Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.logJobsOnFailure(t)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = q.Stop(ctx)
	})
	return q
}

// enqueue inserts a kms.rewrap job and returns its id.
func (e *env) enqueue(t *testing.T, q *jobs.Queue, batch int) int64 {
	t.Helper()
	ctx := context.Background()
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	jobID, err := q.Enqueue(ctx, tx, contentkey.RewrapArgs{BatchSize: batch}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return jobID
}

func (e *env) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// waitFor polls cond until it holds or the test times out.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitIdle waits until no content key is off target and no kms.rewrap job is waiting or running.
func (e *env) waitIdle(t *testing.T, target db.KEKRef) {
	t.Helper()
	waitFor(t, "the re-wrap to finish", func() bool {
		left, err := e.repos.CountContentKeysNotOnKEK(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		return left == 0 && e.count(t, "SELECT count(*) FROM river_job WHERE state IN ('available','scheduled','running','retryable','pending')") == 0
	})
}

// logJobsOnFailure prints the queue's job states (kind, state, attempt, stored error) when the
// test fails. The stored error is a fixed string with the code only.
func (e *env) logJobsOnFailure(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		rows, err := e.pool.Query(context.Background(), "SELECT id, kind, state::text, attempt, COALESCE(errors::text, '') FROM river_job ORDER BY id")
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var (
				id            int64
				kind, state   string
				attempt       int
				storedFailure string
			)
			if rows.Scan(&id, &kind, &state, &attempt, &storedFailure) == nil {
				t.Logf("job %d %s %s attempt=%d errors=%s", id, kind, state, attempt, storedFailure)
			}
		}
	})
}

func (e *env) usage(t *testing.T) []db.KEKUsage {
	t.Helper()
	u, err := e.repos.CountContentKeysByKEK(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// assertKeys checks that every key still unwraps, through mgr, to the same bytes.
func (e *env) assertKeys(t *testing.T, mgr *contentkey.Manager, want map[id.AssetID][]byte) {
	t.Helper()
	for asset, key := range want {
		got, err := mgr.Get(context.Background(), e.tenant.ID, asset)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), key) {
			t.Fatal("a content key changed")
		}
	}
}

// rows returns every content key row in id order, with its wrapped bytes.
func (e *env) rows(t *testing.T) []db.ContentKeyRow {
	t.Helper()
	// Every row is off a KEK that no row uses, so this lists all of them.
	rows, err := e.repos.ListContentKeysNotOnKEK(context.Background(), db.KEKRef{Provider: "none", KeyID: "none", Version: "0"}, id.ContentKeyID{}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

var fastRetry = jobs.KindConfig{
	MaxAttempts: 100,
	Backoff:     func(int) time.Duration { return 100 * time.Millisecond },
}

func localKEK(version string) db.KEKRef {
	return db.KEKRef{Provider: "local", KeyID: "local", Version: version}
}

func TestRewrapJobRotatesLocalKEK(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	keys := e.createN(t, e.mgr, 7)

	if u := e.usage(t); len(u) != 1 || u[0].KEK != localKEK("1") || u[0].Keys != 7 {
		t.Fatalf("usage before = %+v", u)
	}

	// Rotate: a process started with version 2 current still holds version 1 for unwrap.
	v2 := e.manager(t, localProvider(t, 2))
	q := e.startWorker(t, v2, fastRetry)
	e.enqueue(t, q, 3)
	e.waitIdle(t, localKEK("2"))

	if u := e.usage(t); len(u) != 1 || u[0].KEK != localKEK("2") || u[0].Keys != 7 {
		t.Fatalf("usage after = %+v", u)
	}
	e.assertKeys(t, v2, keys)
	for _, r := range e.rows(t) {
		if r.RewrappedAt == nil {
			t.Fatal("rewrapped_at is not set")
		}
	}
	// 7 keys in batches of 3 take three runs: the job chains itself.
	if n := e.count(t, "SELECT count(*) FROM river_job WHERE kind = 'kms.rewrap' AND state = 'completed'"); n != 3 {
		t.Fatalf("completed re-wrap runs = %d, want 3", n)
	}
	if dead, _, err := q.ListDead(ctx, "", 10); err != nil || len(dead) != 0 {
		t.Fatalf("dead letters = %v, %v", dead, err)
	}

	// A second run changes nothing and does not chain.
	before := e.rows(t)
	e.enqueue(t, q, 3)
	e.waitIdle(t, localKEK("2"))
	waitFor(t, "the second run to complete", func() bool {
		return e.count(t, "SELECT count(*) FROM river_job WHERE kind = 'kms.rewrap' AND state = 'completed'") == 4
	})
	for i, r := range e.rows(t) {
		if !bytes.Equal(r.Wrapped, before[i].Wrapped) || r.KEK != before[i].KEK {
			t.Fatal("an idempotent run changed a row")
		}
	}
	e.assertKeys(t, v2, keys)
}

func TestRewrapConcurrentRunsAreSafe(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	keys := e.createN(t, e.mgr, 12)
	v2 := e.manager(t, localProvider(t, 2))

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// One run may find every row already moved by the other and report that as a
			// retryable failure; the final state is what matters.
			_, _ = v2.Rewrap(ctx, 100, nil)
		}()
	}
	wg.Wait()
	for range 3 {
		if _, err := v2.Rewrap(ctx, 100, nil); err != nil {
			t.Fatal(err)
		}
	}
	if u := e.usage(t); len(u) != 1 || u[0].KEK != localKEK("2") || u[0].Keys != 12 {
		t.Fatalf("usage = %+v", u)
	}
	e.assertKeys(t, v2, keys)
}

func TestUpdateIsGuardedByOldKEK(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	e.createN(t, e.mgr, 1)
	row := e.rows(t)[0]

	u := db.RewrapUpdate{
		ID: row.ID, From: localKEK("1"), To: localKEK("2"),
		EnvelopeVersion: contentkey.EnvelopeVersion, Wrapped: []byte("new-ciphertext"),
	}
	if ok, err := e.repos.UpdateContentKeyWrapped(ctx, u); err != nil || !ok {
		t.Fatalf("first update = %v, %v", ok, err)
	}
	// A second writer that still believes the row is on version 1 must not overwrite it.
	stale := u
	stale.Wrapped = []byte("stale-ciphertext")
	if ok, err := e.repos.UpdateContentKeyWrapped(ctx, stale); err != nil || ok {
		t.Fatalf("stale update = %v, %v; want false", ok, err)
	}
	if got := e.rows(t)[0]; !bytes.Equal(got.Wrapped, []byte("new-ciphertext")) || got.KEK != localKEK("2") {
		t.Fatal("the stale update changed the row")
	}
}

func TestRewrapOutageRetriesAndRecovers(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	keys := e.createN(t, e.mgr, 6)
	before := e.rows(t)

	f := kmstest.NewFaulty(localProvider(t, 2))
	// Each key takes three provider calls (unwrap, wrap, verifying unwrap): the first batch of two
	// keys completes (6 calls), and the outage starts in the middle of the second batch.
	f.FailAfter(7)
	mgr := e.manager(t, f)
	q := e.startWorker(t, mgr, fastRetry)
	e.enqueue(t, q, 2)

	waitFor(t, "the job to retry after the outage", func() bool {
		return e.count(t, "SELECT count(*) FROM river_job WHERE kind = 'kms.rewrap' AND state IN ('retryable','available','running') AND attempt >= 2 AND errors::text LIKE '%code=dependency_unavailable%'") == 1
	})

	// Completed rows are re-wrapped; the rest are untouched, byte for byte.
	after := e.rows(t)
	for i, r := range after {
		if i < 2 {
			if r.KEK != localKEK("2") {
				t.Fatalf("row %d was not re-wrapped", i)
			}
			continue
		}
		if r.KEK != localKEK("1") || !bytes.Equal(r.Wrapped, before[i].Wrapped) || r.RewrappedAt != nil {
			t.Fatalf("row %d changed during the outage", i)
		}
	}

	// The outage ends; the retry finishes the work.
	f.FailAfter(-1)
	e.waitIdle(t, localKEK("2"))
	e.assertKeys(t, mgr, keys)
	if dead, _, err := q.ListDead(ctx, "", 10); err != nil || len(dead) != 0 {
		t.Fatalf("dead letters = %v, %v", dead, err)
	}
}

func TestRewrapIntegrityFailureCancelsAndIsDeadLettered(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	keys := e.createN(t, e.mgr, 4)
	before := e.rows(t)

	// Corrupt the second row's ciphertext.
	if _, err := e.pool.Exec(ctx, "UPDATE content_keys SET wrapped = set_byte(wrapped, 20, get_byte(wrapped, 20) # 1) "+
		"WHERE id = (SELECT id FROM content_keys ORDER BY id OFFSET 1 LIMIT 1)"); err != nil {
		t.Fatal(err)
	}

	v2 := e.manager(t, localProvider(t, 2))
	q := e.startWorker(t, v2, fastRetry)
	jobID := e.enqueue(t, q, 100)
	waitFor(t, "the job to be cancelled", func() bool {
		dead, _, err := q.ListDead(ctx, "", 10)
		return err == nil && len(dead) == 1
	})
	dead, _, err := q.ListDead(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if d := dead[0]; d.ID != jobID || d.Kind != contentkey.RewrapKind || d.State != "cancelled" || d.LastErrorCode != "internal_error" || d.Attempts != 1 {
		t.Fatalf("dead letter = %+v", d)
	}

	// The row before the failure moved; the corrupt row and the rest stay where they were.
	after := e.rows(t)
	if after[0].KEK != localKEK("2") {
		t.Fatal("the row before the failure was not re-wrapped")
	}
	for i := 1; i < len(after); i++ {
		if after[i].KEK != localKEK("1") || after[i].RewrappedAt != nil {
			t.Fatalf("row %d changed", i)
		}
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "content key failed authentication (integrity failure)") || !strings.Contains(logs, before[1].ID.String()) {
		t.Fatal("the integrity failure was not logged with its identifiers")
	}
	for _, k := range keys {
		assertNoKey(t, k, logs)
	}
}

// TestLogsNeverHoldKeyMaterial runs Create, Get, Rewrap and an outage with a capturing JSON log
// handler, and asserts that neither a content key nor a KEK appears in logs or error strings.
func TestLogsNeverHoldKeyMaterial(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	var outs []string
	note := func(err error) {
		if err == nil {
			return
		}
		outs = append(outs, err.Error())
		for u := errors.Unwrap(err); u != nil; u = errors.Unwrap(u) {
			outs = append(outs, u.Error())
		}
	}

	keys := e.createN(t, e.mgr, 3)
	for asset := range keys {
		_, err := e.mgr.Get(ctx, e.tenant.ID, asset)
		note(err)
	}

	v2 := e.manager(t, localProvider(t, 2))
	for range 2 {
		res, err := v2.Rewrap(ctx, 2, nil)
		note(err)
		outs = append(outs, fmt.Sprintf("%+v", res))
	}

	// An outage in every operation.
	f := kmstest.NewFaulty(localProvider(t, 2))
	f.SetOutage(true)
	down := e.manager(t, f)
	asset := e.newAsset(t, e.tenant, e.client)
	for _, a := range []id.AssetID{asset} {
		err := db.Tx(ctx, e.pool, func(tx *db.Repos) error {
			_, err := down.Create(ctx, tx, e.tenant.ID, a)
			return err
		})
		wantCode(t, err, errs.DependencyUnavailable)
		note(err)
	}
	for a := range keys {
		_, err := down.Get(ctx, e.tenant.ID, a)
		wantCode(t, err, errs.DependencyUnavailable)
		note(err)
		break
	}
	_, err := down.Rewrap(ctx, 10, nil)
	wantCode(t, err, errs.DependencyUnavailable)
	note(err)

	// An integrity failure in Get and in Rewrap.
	f.SetOutage(false)
	f.SetIntegrityFailure(true)
	for a := range keys {
		_, err := down.Get(ctx, e.tenant.ID, a)
		wantCode(t, err, errs.InternalError)
		note(err)
		break
	}

	outs = append(outs, e.logs.String())
	if e.logs.String() == "" {
		t.Fatal("the capture saw no logs")
	}
	secrets := make([][]byte, 0, len(keys)+2)
	for _, k := range keys {
		secrets = append(secrets, k)
	}
	for _, kek := range kekSet() {
		secrets = append(secrets, kek)
	}
	for _, s := range secrets {
		assertNoKey(t, s, outs...)
	}
}

func TestCheckKEKsAgainstDatabase(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	e.createN(t, e.mgr, 2)

	ok, err := kms.NewRegistry(localProvider(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	if err := contentkey.CheckKEKs(ctx, e.repos, ok); err != nil {
		t.Fatalf("version 1 is still configured: %v", err)
	}

	// Version 1 has been removed from the KEK set while keys still use it.
	only2, err := local.NewFromKeys(config.Development, map[int][]byte{2: kekSet()[2]}, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := kms.NewRegistry(only2)
	if err != nil {
		t.Fatal(err)
	}
	err = contentkey.CheckKEKs(ctx, e.repos, reg)
	if err == nil || !strings.Contains(err.Error(), "local version 1") {
		t.Fatalf("got %v, want a refusal naming local version 1", err)
	}
	if strings.Contains(err.Error(), "version 2") {
		t.Fatal("the message names a version that is configured")
	}

	// The provider that wrapped the keys is not configured at all.
	reg, err = kms.NewRegistry(&renamed{Provider: localProvider(t, 2), name: "vault"})
	if err != nil {
		t.Fatal(err)
	}
	err = contentkey.CheckKEKs(ctx, e.repos, reg)
	if err == nil || !strings.Contains(err.Error(), "local") || !strings.Contains(err.Error(), config.EnvKMSUnwrapProviders) {
		t.Fatalf("got %v, want a refusal naming provider local", err)
	}
}

// renamed presents a provider under another name and is not a kms.KEKChecker.
type renamed struct {
	kms.Provider
	name string
}

func (r *renamed) Name() string { return r.name }

// --- provider migration against an OpenBao Transit server ---

const (
	openBaoImage = "openbao/openbao:2.7.2@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f"
	baoRootToken = "rewrap-integration-root-token" //nolint:gosec // dev server only
)

type baoServer struct {
	ctr  testcontainers.Container
	addr string
}

func startOpenBao(t *testing.T) *baoServer {
	t.Helper()
	ctx := context.Background()
	ctr, err := testcontainers.Run(ctx, openBaoImage,
		testcontainers.WithExposedPorts("8200/tcp"),
		testcontainers.WithEnv(map[string]string{"BAO_DEV_ROOT_TOKEN_ID": baoRootToken}),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/v1/sys/health").WithPort("8200/tcp").WithStartupTimeout(2*time.Minute)),
	)
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("cannot start the OpenBao container: %v", err)
	}
	addr, err := ctr.PortEndpoint(ctx, "8200/tcp", "http")
	if err != nil {
		t.Fatal(err)
	}
	s := &baoServer{ctr: ctr, addr: addr}
	s.post(t, "/v1/sys/mounts/transit", `{"type":"transit"}`)
	s.post(t, "/v1/transit/keys/cipherframe", `{"type":"aes256-gcm96"}`)
	return s
}

func (s *baoServer) post(t *testing.T, path, body string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", baoRootToken)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("POST %s: status %d", path, resp.StatusCode)
	}
}

func (s *baoServer) provider(t *testing.T) *vault.Provider {
	t.Helper()
	p, err := vault.New(config.KMSVault{
		Addr: s.addr, Token: config.NewSecret(baoRootToken), TransitMount: "transit", KeyName: "cipherframe",
		Timeout: 3 * time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRewrapMovesKeysFromLocalToVault(t *testing.T) {
	ctx := context.Background()
	bao := startOpenBao(t)
	e := newEnv(t, localProvider(t, 1))
	keys := e.createN(t, e.mgr, 5)

	// local is unwrap-only; vault wraps from now on.
	vp := bao.provider(t)
	mgr := e.manager(t, vp, localProvider(t, 1))
	reg, err := kms.NewRegistry(vp, localProvider(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := contentkey.CheckKEKs(ctx, e.repos, reg); err != nil {
		t.Fatalf("startup check with local as an unwrap provider: %v", err)
	}
	// Without local the process must refuse to start.
	noLocal, err := kms.NewRegistry(vp)
	if err != nil {
		t.Fatal(err)
	}
	if err := contentkey.CheckKEKs(ctx, e.repos, noLocal); err == nil || !strings.Contains(err.Error(), "local") {
		t.Fatalf("got %v, want a refusal naming local", err)
	}

	// Existing keys stay readable before the re-wrap.
	e.assertKeys(t, mgr, keys)

	ref, err := vp.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	target := db.KEKRef{Provider: "vault", KeyID: ref.KeyID, Version: ref.Version}
	q := e.startWorker(t, mgr, fastRetry)
	e.enqueue(t, q, 2)
	e.waitIdle(t, target)

	if u := e.usage(t); len(u) != 1 || u[0].KEK != target || u[0].Keys != 5 {
		t.Fatalf("usage = %+v, want all 5 keys on %+v", u, target)
	}
	e.assertKeys(t, mgr, keys)

	// The old provider can now be dropped from the configuration.
	if err := contentkey.CheckKEKs(ctx, e.repos, noLocal); err != nil {
		t.Fatalf("after the re-wrap the startup check must pass without local: %v", err)
	}
	e.assertKeys(t, e.manager(t, vp), keys)
}

// stopAfterWraps stops a container once the provider has wrapped n keys, which ends the key
// service in the middle of a re-wrap.
type stopAfterWraps struct {
	kms.Provider
	after int32
	n     atomic.Int32
	stop  func()
}

func (s *stopAfterWraps) Wrap(ctx context.Context, pt, aad []byte) (kms.Wrapped, error) {
	w, err := s.Provider.Wrap(ctx, pt, aad)
	if err == nil && s.n.Add(1) == s.after {
		s.stop()
	}
	return w, err
}

func TestRewrapOutageOfVaultMidRun(t *testing.T) {
	ctx := context.Background()
	bao := startOpenBao(t)
	e := newEnv(t, localProvider(t, 1))
	keys := e.createN(t, e.mgr, 6)
	before := e.rows(t)

	vp := &stopAfterWraps{Provider: bao.provider(t), after: 3, stop: func() {
		timeout := 5 * time.Second
		if err := bao.ctr.Stop(ctx, &timeout); err != nil {
			t.Errorf("cannot stop the container: %v", err)
		}
	}}
	mgr := e.manager(t, vp, localProvider(t, 1))
	q := e.startWorker(t, mgr, fastRetry)
	e.enqueue(t, q, 2)

	waitFor(t, "the job to retry after the outage", func() bool {
		return e.count(t, "SELECT count(*) FROM river_job WHERE kind = 'kms.rewrap' AND state IN ('retryable','available','running') AND attempt >= 2 AND errors::text LIKE '%code=dependency_unavailable%'") == 1
	})

	// The first batch completed; the rest stayed on local, untouched.
	after := e.rows(t)
	for i, r := range after {
		if i < 2 {
			if r.KEK.Provider != "vault" {
				t.Fatalf("row %d was not re-wrapped", i)
			}
			continue
		}
		if r.KEK != localKEK("1") || !bytes.Equal(r.Wrapped, before[i].Wrapped) || r.RewrappedAt != nil {
			t.Fatalf("row %d changed during the outage", i)
		}
	}
	// Keys still on local stay readable while the key service is down.
	for i := 2; i < len(after); i++ {
		got, err := mgr.Get(ctx, e.tenant.ID, after[i].AssetID)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), keys[after[i].AssetID]) {
			t.Fatal("a key on the surviving provider changed")
		}
	}
	// A key on the unavailable provider fails closed, as retryable.
	_, err := mgr.Get(ctx, e.tenant.ID, after[0].AssetID)
	wantCode(t, err, errs.DependencyUnavailable)
}
