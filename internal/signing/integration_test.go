//go:build integration

package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
)

func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }

type env struct {
	pool   *pgxpool.Pool
	repos  *db.Repos
	faulty *kmstest.Faulty
	reg    *kms.Registry
	mgr    *Manager
	logs   *lockedBuffer
	tenant db.Tenant
	client db.Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool := dbtest.NewMigrated(t)
	faulty := kmstest.NewFaulty(testProvider(t))
	reg, err := kms.NewRegistry(faulty)
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	e := &env{pool: pool, repos: db.New(pool), faulty: faulty, reg: reg, logs: logs}
	e.mgr = NewManager(pool, reg, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	ctx := context.Background()
	if e.tenant, err = e.repos.CreateTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if e.client, err = e.repos.CreateClient(ctx, e.tenant.ID, "ops"); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) audit() Audit {
	return Audit{TenantID: e.tenant.ID, Actor: auth.Actor{ClientID: e.client.ID, RequestID: "0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f35"}}
}

func wantCode(t *testing.T, err error, code errs.Code) {
	t.Helper()
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error %v, want code %s", err, code)
	}
}

func (e *env) count(t *testing.T) int {
	t.Helper()
	n, err := e.repos.CountSigningKeys(context.Background(), PurposeIntegrity)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEnsureCurrentCreatesOneKeyUnderConcurrency(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errc := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errc <- e.mgr.EnsureCurrent(ctx)
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := e.count(t); n != 1 {
		t.Fatalf("keys = %d, want 1", n)
	}
	// Idempotent afterwards.
	if err := e.mgr.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t); n != 1 {
		t.Fatalf("keys = %d after a repeat, want 1", n)
	}
	keys, err := e.mgr.PublicKeys(ctx)
	if err != nil || len(keys) != 1 || !keys[0].Current || keys[0].Status != StateActive || keys[0].Algorithm != AlgEd25519 {
		t.Fatalf("keys = %+v, err = %v", keys, err)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	msg := []byte("test-fixture-manifest-bytes")
	keyID, sig, err := e.mgr.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	// Verify the way a client does: from the published key set only.
	keys, err := NewKeySet(e.repos, 0, nil).Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var pub ed25519.PublicKey
	for _, k := range keys {
		if k.KeyID == keyID {
			raw, err := base64.StdEncoding.DecodeString(k.PublicKeyBase64())
			if err != nil {
				t.Fatal(err)
			}
			pub = raw
		}
	}
	if pub == nil || !ed25519.Verify(pub, msg, sig) {
		t.Fatal("the signature does not verify with the published key")
	}
	if ed25519.Verify(pub, []byte("other"), sig) {
		t.Fatal("the signature verifies another message")
	}
	// A second Sign uses the cache: no further key-service call.
	before := e.faulty.Calls()
	if _, _, err := e.mgr.Sign(ctx, msg); err != nil {
		t.Fatal(err)
	}
	if got := e.faulty.Calls(); got != before {
		t.Fatalf("key-service calls rose from %d to %d on a cached sign", before, got)
	}
}

func TestSignWithoutKey(t *testing.T) {
	e := newEnv(t)
	_, _, err := e.mgr.Sign(context.Background(), []byte("m"))
	wantCode(t, err, errs.InternalError)
}

func TestRotationKeepsOldKeyVerifying(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	msg := []byte("test-fixture-record")
	oldID, oldSig, err := e.mgr.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	nk, err := e.mgr.Rotate(ctx, e.audit())
	if err != nil {
		t.Fatal(err)
	}
	if nk.KeyID == oldID || !nk.Current || nk.Status != StateActive {
		t.Fatalf("rotated key = %+v", nk)
	}
	newID, newSig, err := e.mgr.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if newID != nk.KeyID {
		t.Fatalf("signed with %s, want the new current key %s", newID, nk.KeyID)
	}
	keys, err := e.mgr.PublicKeys(ctx)
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys = %+v, err = %v", keys, err)
	}
	if keys[0].KeyID != oldID || keys[0].Status != StateActive || keys[0].Current {
		t.Fatalf("old key = %+v, want active and not current", keys[0])
	}
	if keys[1].KeyID != newID || !keys[1].Current {
		t.Fatalf("new key = %+v", keys[1])
	}
	if !ed25519.Verify(keys[0].PublicKey, msg, oldSig) || !ed25519.Verify(keys[1].PublicKey, msg, newSig) {
		t.Fatal("a signature does not verify with its key after rotation")
	}
	// The audit event names the rotation and the new key id, and no secret.
	evs, err := e.repos.ListAuditEvents(ctx, e.tenant.ID, nil, 10)
	if err != nil || len(evs) != 1 || evs[0].Action != AuditRotate || evs[0].Target != nk.KeyID || evs[0].ClientID != e.client.ID {
		t.Fatalf("audit = %+v, err = %v", evs, err)
	}
}

func TestRetire(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	first, _ := e.mgr.PublicKeys(ctx)
	// The current key cannot be retired.
	_, err := e.mgr.Retire(ctx, first[0].KeyID, e.audit())
	wantCode(t, err, errs.Conflict)
	if _, err := e.mgr.Rotate(ctx, e.audit()); err != nil {
		t.Fatal(err)
	}
	// Prime the cache with the old key's seed path is not possible (it only signs when current);
	// retire it.
	r, err := e.mgr.Retire(ctx, first[0].KeyID, e.audit())
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StateRetired || r.RetiredAt == nil || r.Current {
		t.Fatalf("retired key = %+v", r)
	}
	// Retiring again changes nothing and is not audited twice.
	r2, err := e.mgr.Retire(ctx, first[0].KeyID, e.audit())
	if err != nil || !r2.RetiredAt.Equal(*r.RetiredAt) {
		t.Fatalf("second retire = %+v, err = %v", r2, err)
	}
	// Unknown and malformed ids are not_found.
	_, err = e.mgr.Retire(ctx, "sk_00000000000000000000000001", e.audit())
	wantCode(t, err, errs.NotFound)
	_, err = e.mgr.Retire(ctx, "nope", e.audit())
	wantCode(t, err, errs.NotFound)

	keys, _ := e.mgr.PublicKeys(ctx)
	if len(keys) != 2 || keys[0].Status != StateRetired || keys[1].Status != StateActive {
		t.Fatalf("keys = %+v: a retired key must stay published", keys)
	}
	// Signing never uses the retired key.
	id, _, err := e.mgr.Sign(ctx, []byte("m"))
	if err != nil || id != keys[1].KeyID {
		t.Fatalf("signed with %s (err %v), want %s", id, err, keys[1].KeyID)
	}
	evs, _ := e.repos.ListAuditEvents(ctx, e.tenant.ID, nil, 10)
	var retires int
	for _, ev := range evs {
		if ev.Action == AuditRetire {
			retires++
		}
	}
	if retires != 1 {
		t.Fatalf("retire audit events = %d, want 1", retires)
	}
}

func TestKMSOutageCreatesNoKeyAndSignsNothing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.faulty.SetOutage(true)
	wantCode(t, e.mgr.EnsureCurrent(ctx), errs.DependencyUnavailable)
	_, err := e.mgr.Rotate(ctx, e.audit())
	wantCode(t, err, errs.DependencyUnavailable)
	if n := e.count(t); n != 0 {
		t.Fatalf("keys = %d after failed creations, want 0", n)
	}
	evs, _ := e.repos.ListAuditEvents(ctx, e.tenant.ID, nil, 10)
	if len(evs) != 0 {
		t.Fatalf("audit events = %d for a failed rotation, want 0", len(evs))
	}

	e.faulty.SetOutage(false)
	if err := e.mgr.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	e.mgr.Close() // cold cache
	e.faulty.SetOutage(true)
	_, _, err = e.mgr.Sign(ctx, []byte("m"))
	wantCode(t, err, errs.DependencyUnavailable)
	if n := e.count(t); n != 1 {
		t.Fatalf("keys = %d, want 1", n)
	}
}

func TestEnvelopeMovedToAnotherKeyDoesNotOpen(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	first, _ := e.mgr.PublicKeys(ctx)
	if _, err := e.mgr.Rotate(ctx, e.audit()); err != nil {
		t.Fatal(err)
	}
	a, err := e.repos.GetSigningKey(ctx, first[0].KeyID)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := e.repos.GetCurrentSigningKey(ctx, PurposeIntegrity)
	if err != nil {
		t.Fatal(err)
	}
	// Copy the old key's envelope onto the current key's row.
	if _, err := e.pool.Exec(ctx, `UPDATE signing_keys SET private_envelope = $1 WHERE key_id = $2`, a.PrivateEnvelope, cur.KeyID); err != nil {
		t.Fatal(err)
	}
	_, _, err = e.mgr.Sign(ctx, []byte("m"))
	wantCode(t, err, errs.InternalError)
}

func TestSchemaInvariants(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.mgr.Rotate(ctx, Audit{}); err != nil {
		t.Fatal(err)
	}
	var current int
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE is_current`).Scan(&current); err != nil || current != 1 {
		t.Fatalf("current keys = %d, err = %v", current, err)
	}
	// A second current key is refused by the partial unique index.
	_, err := e.pool.Exec(ctx, `INSERT INTO signing_keys (key_id, purpose, algorithm, public_key, private_envelope, state, is_current)
		VALUES ('sk_00000000000000000000000002', 'integrity', 'ed25519', $1, '\x01', 'active', true)`, bytes.Repeat([]byte{7}, 32))
	if err == nil {
		t.Fatal("a second current key was accepted")
	}
	// A retired key cannot be current, and a short public key is refused.
	for name, q := range map[string]string{
		"retired current": `INSERT INTO signing_keys (key_id, purpose, algorithm, public_key, private_envelope, state, is_current, retired_at)
			VALUES ('sk_00000000000000000000000003', 'integrity', 'ed25519', '\x0808080808080808080808080808080808080808080808080808080808080808', '\x01', 'retired', true, now())`,
		"short public key": `INSERT INTO signing_keys (key_id, purpose, algorithm, public_key, private_envelope, state)
			VALUES ('sk_00000000000000000000000004', 'integrity', 'ed25519', '\x01', '\x01', 'active')`,
		"null envelope": `INSERT INTO signing_keys (key_id, purpose, algorithm, public_key, private_envelope, state)
			VALUES ('sk_00000000000000000000000005', 'integrity', 'ed25519', '\x0909090909090909090909090909090909090909090909090909090909090909', NULL, 'active')`,
	} {
		if _, err := e.pool.Exec(ctx, q); err == nil {
			t.Errorf("%s: the insert was accepted", name)
		}
	}
}

func TestNoPrivateMaterialInLogsOrErrors(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.EnsureCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.mgr.Rotate(ctx, e.audit()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.mgr.Sign(ctx, []byte("m")); err != nil {
		t.Fatal(err)
	}
	var errTexts []string
	e.faulty.SetOutage(true)
	e.mgr.Close()
	_, _, err := e.mgr.Sign(ctx, []byte("m"))
	errTexts = append(errTexts, err.Error())
	e.faulty.SetOutage(false)

	// Collect every secret form: seed and private key (hex, base64, raw), and the stored envelopes.
	cur, err := e.repos.GetCurrentSigningKey(ctx, PurposeIntegrity)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := e.mgr.open(ctx, cur)
	if err != nil {
		t.Fatal(err)
	}
	forms := [][]byte{priv.Seed(), priv, cur.PrivateEnvelope}
	for _, f := range forms {
		cands := [][]byte{f, []byte(hex.EncodeToString(f)), []byte(base64.StdEncoding.EncodeToString(f)), []byte(base64.RawURLEncoding.EncodeToString(f))}
		for _, c := range cands {
			if bytes.Contains([]byte(e.logs.String()), c) {
				t.Fatal("the logs contain private key material")
			}
			for _, et := range errTexts {
				if bytes.Contains([]byte(et), c) {
					t.Fatal("an error text contains private key material")
				}
			}
		}
	}
	if e.logs.String() == "" {
		t.Fatal("expected the manager to log the key creation")
	}
}
