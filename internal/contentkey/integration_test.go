//go:build integration

package contentkey_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/local"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }

func kekSet() map[int][]byte {
	return map[int][]byte{
		1: bytes.Repeat([]byte{0x41}, config.KEKBytes),
		2: bytes.Repeat([]byte{0x42}, config.KEKBytes),
	}
}

func localProvider(t *testing.T, current int) *local.Provider {
	t.Helper()
	p, err := local.NewFromKeys(config.Development, kekSet(), current, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// lockedBuffer is a goroutine-safe log sink.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type env struct {
	pool   *pgxpool.Pool
	repos  *db.Repos
	mgr    *contentkey.Manager
	logs   *lockedBuffer
	tenant db.Tenant
	client db.Client
}

func newEnv(t *testing.T, current kms.Provider, others ...kms.Provider) *env {
	t.Helper()
	pool := dbtest.NewMigrated(t)
	reg, err := kms.NewRegistry(current, others...)
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	e := &env{pool: pool, repos: db.New(pool), logs: logs}
	e.mgr = contentkey.NewManager(pool, reg, newLogger(logs))
	e.tenant, e.client = e.newTenant(t, "acme")
	return e
}

func (e *env) newTenant(t *testing.T, name string) (db.Tenant, db.Client) {
	t.Helper()
	ctx := context.Background()
	tn, err := e.repos.CreateTenant(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := e.repos.CreateClient(ctx, tn.ID, name+"-client")
	if err != nil {
		t.Fatal(err)
	}
	return tn, cl
}

func (e *env) newAsset(t *testing.T, tn db.Tenant, cl db.Client) id.AssetID {
	t.Helper()
	a, err := e.repos.CreateAsset(context.Background(), tn.ID, cl.ID, db.AssetCreated)
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

// create runs Create in its own transaction.
func (e *env) create(ctx context.Context, tn id.TenantID, asset id.AssetID) (contentkey.ContentKey, error) {
	var k contentkey.ContentKey
	err := db.Tx(ctx, e.pool, func(tx *db.Repos) error {
		var err error
		k, err = e.mgr.Create(ctx, tx, tn, asset, keys.Original)
		return err
	})
	return k, err
}

func (e *env) destroy(ctx context.Context, tn id.TenantID, asset id.AssetID) (bool, error) {
	var ok bool
	err := db.Tx(ctx, e.pool, func(tx *db.Repos) error {
		var err error
		ok, err = e.mgr.Destroy(ctx, tx, tn, asset)
		return err
	})
	return ok, err
}

func wantCode(t *testing.T, err error, code errs.Code) {
	t.Helper()
	var e *errs.Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not an *errs.Error, want %s", err, code)
	}
	if e.Code != code {
		t.Fatalf("code = %s, want %s (%v)", e.Code, code, err)
	}
}

func countRows(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM content_keys").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func assertNoKey(t *testing.T, key []byte, outs ...string) {
	t.Helper()
	for _, f := range []string{
		string(key), hex.EncodeToString(key), strings.ToUpper(hex.EncodeToString(key)),
		base64.StdEncoding.EncodeToString(key), base64.RawStdEncoding.EncodeToString(key),
		base64.URLEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key),
	} {
		for _, o := range outs {
			if strings.Contains(o, f) {
				t.Fatal("key material appears in output")
			}
		}
	}
}

func TestCreateGetRoundTrip(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	asset := e.newAsset(t, e.tenant, e.client)

	created, err := e.create(ctx, e.tenant.ID, asset)
	if err != nil {
		t.Fatal(err)
	}
	if len(created.Bytes()) != contentkey.KeyBytes || bytes.Equal(created.Bytes(), make([]byte, contentkey.KeyBytes)) {
		t.Fatal("expected a random 16-byte key")
	}
	if created.AssetID() != asset || created.ID().IsZero() {
		t.Fatal("identifiers not set")
	}

	got, err := e.mgr.Get(ctx, e.tenant.ID, asset, keys.Original)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), created.Bytes()) || got.ID() != created.ID() {
		t.Fatal("Get returned a different key")
	}

	// The stored row is wrapped: it records the KEK and never contains the plaintext key.
	row, err := e.repos.GetContentKey(ctx, e.tenant.ID, asset, keys.Original)
	if err != nil {
		t.Fatal(err)
	}
	if row.KEK != (db.KEKRef{Provider: "local", KeyID: "local", Version: "1"}) || row.EnvelopeVersion != contentkey.EnvelopeVersion {
		t.Fatalf("unexpected KEK record: %+v", row)
	}
	if bytes.Contains(row.Wrapped, created.Bytes()) {
		t.Fatal("the stored bytes contain the plaintext key")
	}
	assertNoKey(t, created.Bytes(), e.logs.String())
}

func TestCreateTwiceConflicts(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	asset := e.newAsset(t, e.tenant, e.client)

	first, err := e.create(ctx, e.tenant.ID, asset)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.create(ctx, e.tenant.ID, asset)
	wantCode(t, err, errs.Conflict)
	if n := countRows(t, e.pool); n != 1 {
		t.Fatalf("%d content keys for one asset, want 1 (I7)", n)
	}
	got, err := e.mgr.Get(ctx, e.tenant.ID, asset, keys.Original)
	if err != nil || !bytes.Equal(got.Bytes(), first.Bytes()) {
		t.Fatal("the first key was replaced by a second Create")
	}
}

// TestCreateRaceLeavesOneKey runs Create concurrently for one asset: exactly one wins, the rest
// get conflict (the unique constraint, not the pre-check, is the authority).
func TestCreateRaceLeavesOneKey(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	asset := e.newAsset(t, e.tenant, e.client)

	const n = 8
	errc := make(chan error, n)
	for range n {
		go func() { _, err := e.create(ctx, e.tenant.ID, asset); errc <- err }()
	}
	won := 0
	for range n {
		err := <-errc
		if err == nil {
			won++
			continue
		}
		wantCode(t, err, errs.Conflict)
	}
	if won != 1 || countRows(t, e.pool) != 1 {
		t.Fatalf("winners = %d, rows = %d; want 1 and 1", won, countRows(t, e.pool))
	}
}

func TestDestroyThenGetIsNotFound(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	asset := e.newAsset(t, e.tenant, e.client)
	if _, err := e.create(ctx, e.tenant.ID, asset); err != nil {
		t.Fatal(err)
	}

	ok, err := e.destroy(ctx, e.tenant.ID, asset)
	if err != nil || !ok {
		t.Fatalf("Destroy = %v, %v", ok, err)
	}
	_, err = e.mgr.Get(ctx, e.tenant.ID, asset, keys.Original)
	wantCode(t, err, errs.NotFound)
	if n := countRows(t, e.pool); n != 0 {
		t.Fatalf("the row survived Destroy (%d rows): crypto-shredding must delete it", n)
	}
	if ok, err := e.destroy(ctx, e.tenant.ID, asset); err != nil || ok {
		t.Fatalf("second Destroy = %v, %v; want false", ok, err)
	}
	// A new key can be created afterwards, and it is a different key.
	if _, err := e.create(ctx, e.tenant.ID, asset); err != nil {
		t.Fatal(err)
	}
}

func TestDestroyRollsBackWithTransaction(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	asset := e.newAsset(t, e.tenant, e.client)
	if _, err := e.create(ctx, e.tenant.ID, asset); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("abort")
	err := db.Tx(ctx, e.pool, func(tx *db.Repos) error {
		if _, err := e.mgr.Destroy(ctx, tx, e.tenant.ID, asset); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if _, err := e.mgr.Get(ctx, e.tenant.ID, asset, keys.Original); err != nil {
		t.Fatalf("a rolled-back Destroy must keep the key: %v", err)
	}
}

func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	other, otherClient := e.newTenant(t, "globex")
	asset := e.newAsset(t, e.tenant, e.client)
	otherAsset := e.newAsset(t, other, otherClient)

	// Another tenant cannot create a key for this tenant's asset.
	_, err := e.create(ctx, other.ID, asset)
	wantCode(t, err, errs.NotFound)
	if n := countRows(t, e.pool); n != 0 {
		t.Fatalf("a cross-tenant Create left %d rows", n)
	}

	owned, err := e.create(ctx, e.tenant.ID, asset)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.create(ctx, other.ID, otherAsset); err != nil {
		t.Fatal(err)
	}

	_, err = e.mgr.Get(ctx, other.ID, asset, keys.Original)
	wantCode(t, err, errs.NotFound)
	if ok, err := e.destroy(ctx, other.ID, asset); err != nil || ok {
		t.Fatalf("cross-tenant Destroy = %v, %v; want false", ok, err)
	}
	got, err := e.mgr.Get(ctx, e.tenant.ID, asset, keys.Original)
	if err != nil || !bytes.Equal(got.Bytes(), owned.Bytes()) {
		t.Fatal("the owner's key was affected by another tenant")
	}
}

func TestMixedVersionsUnwrapAfterRotation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	asset1 := e.newAsset(t, e.tenant, e.client)
	k1, err := e.create(ctx, e.tenant.ID, asset1)
	if err != nil {
		t.Fatal(err)
	}

	// The current KEK moves to version 2 (a restart with new configuration).
	reg2, err := kms.NewRegistry(localProvider(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	m2 := contentkey.NewManager(e.pool, reg2, newLogger(e.logs))

	got, err := m2.Get(ctx, e.tenant.ID, asset1, keys.Original)
	if err != nil || !bytes.Equal(got.Bytes(), k1.Bytes()) {
		t.Fatalf("a key wrapped under KEK v1 must still unwrap after rotation: %v", err)
	}

	asset2 := e.newAsset(t, e.tenant, e.client)
	var k2 contentkey.ContentKey
	if err := db.Tx(ctx, e.pool, func(tx *db.Repos) error {
		var err error
		k2, err = m2.Create(ctx, tx, e.tenant.ID, asset2, keys.Original)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r1, _ := e.repos.GetContentKey(ctx, e.tenant.ID, asset1, keys.Original)
	r2, _ := e.repos.GetContentKey(ctx, e.tenant.ID, asset2, keys.Original)
	if r1.KEK.Version != "1" || r2.KEK.Version != "2" {
		t.Fatalf("versions = %s and %s, want 1 and 2", r1.KEK.Version, r2.KEK.Version)
	}
	got2, err := m2.Get(ctx, e.tenant.ID, asset2, keys.Original)
	if err != nil || !bytes.Equal(got2.Bytes(), k2.Bytes()) {
		t.Fatal("a key wrapped under KEK v2 must unwrap")
	}
}

// failing wraps a provider and fails every call with a fixed error.
type failing struct {
	kms.Provider
	err error
}

func (f failing) Current(context.Context) (kms.KeyRef, error) { return kms.KeyRef{}, f.err }

func (f failing) Wrap(context.Context, []byte, []byte) (kms.Wrapped, error) {
	return kms.Wrapped{}, f.err
}

func (f failing) Unwrap(context.Context, kms.Wrapped, []byte) ([]byte, error) { return nil, f.err }

func TestProviderFailuresFailClosed(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		err  error
		want errs.Code
	}{
		{"unavailable", kms.New(kms.Unavailable, "local", "wrap", "x"), errs.DependencyUnavailable},
		{"denied", kms.New(kms.Denied, "local", "wrap", "x"), errs.InternalError},
		{"unknown error", errors.New("surprise"), errs.InternalError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, localProvider(t, 1))
			asset := e.newAsset(t, e.tenant, e.client)
			good, err := e.create(ctx, e.tenant.ID, asset)
			if err != nil {
				t.Fatal(err)
			}

			broken, err := kms.NewRegistry(failing{Provider: localProvider(t, 1), err: tc.err})
			if err != nil {
				t.Fatal(err)
			}
			bm := contentkey.NewManager(e.pool, broken, newLogger(e.logs))

			// Create: no key and no row.
			asset2 := e.newAsset(t, e.tenant, e.client)
			var k contentkey.ContentKey
			err = db.Tx(ctx, e.pool, func(tx *db.Repos) error {
				var err error
				k, err = bm.Create(ctx, tx, e.tenant.ID, asset2, keys.Original)
				return err
			})
			wantCode(t, err, tc.want)
			if !k.IsZero() {
				t.Fatal("a failed Create returned a key")
			}
			if n := countRows(t, e.pool); n != 1 {
				t.Fatalf("rows = %d, want 1 (only the earlier key)", n)
			}

			// Get: no key.
			k, err = bm.Get(ctx, e.tenant.ID, asset, keys.Original)
			wantCode(t, err, tc.want)
			if !k.IsZero() {
				t.Fatal("a failed Get returned a key")
			}
			assertNoKey(t, good.Bytes(), e.logs.String(), err.Error())
		})
	}
}

func TestTamperedRowFailsClosedAndLogsIntegrityFailure(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	asset := e.newAsset(t, e.tenant, e.client)
	k, err := e.create(ctx, e.tenant.ID, asset)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx,
		"UPDATE content_keys SET wrapped = set_byte(wrapped, length(wrapped) - 1, get_byte(wrapped, length(wrapped) - 1) # 1)"); err != nil {
		t.Fatal(err)
	}

	got, err := e.mgr.Get(ctx, e.tenant.ID, asset, keys.Original)
	wantCode(t, err, errs.InternalError)
	if !got.IsZero() {
		t.Fatal("a tampered row yielded a key")
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "integrity failure") || !strings.Contains(logs, asset.String()) {
		t.Fatalf("expected an integrity-failure log naming the asset: %s", logs)
	}
	assertNoKey(t, k.Bytes(), logs, err.Error())
}

// TestWrappedKeyCannotMoveToAnotherAsset copies one asset's wrapped bytes into another asset's row
// (as an attacker with database write access might) and shows that unwrap fails.
func TestWrappedKeyCannotMoveToAnotherAsset(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	a1 := e.newAsset(t, e.tenant, e.client)
	a2 := e.newAsset(t, e.tenant, e.client)
	for _, a := range []id.AssetID{a1, a2} {
		if _, err := e.create(ctx, e.tenant.ID, a); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.pool.Exec(ctx,
		"UPDATE content_keys SET wrapped = (SELECT wrapped FROM content_keys WHERE asset_id = $1) WHERE asset_id = $2",
		a1.UUID(), a2.UUID()); err != nil {
		t.Fatal(err)
	}
	got, err := e.mgr.Get(ctx, e.tenant.ID, a2, keys.Original)
	wantCode(t, err, errs.InternalError)
	if !got.IsZero() {
		t.Fatal("a wrapped key moved to another asset unwrapped")
	}
	if _, err := e.mgr.Get(ctx, e.tenant.ID, a1, keys.Original); err != nil {
		t.Fatalf("the original asset's key should be unaffected: %v", err)
	}
	if !strings.Contains(e.logs.String(), "integrity failure") {
		t.Fatal("moving a wrapped key must log an integrity failure")
	}
}

// TestRowRecordsAreAuthenticated edits the recorded KEK version in the row to another configured
// version and shows that unwrap fails rather than trusting the edited metadata.
func TestRowRecordsAreAuthenticated(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	asset := e.newAsset(t, e.tenant, e.client)
	if _, err := e.create(ctx, e.tenant.ID, asset); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, "UPDATE content_keys SET kek_version = '2'"); err != nil {
		t.Fatal(err)
	}
	got, err := e.mgr.Get(ctx, e.tenant.ID, asset, keys.Original)
	wantCode(t, err, errs.InternalError)
	if !got.IsZero() {
		t.Fatal("an edited KEK version unwrapped")
	}
}

func TestUnconfiguredProviderIsAnError(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, localProvider(t, 1))
	asset := e.newAsset(t, e.tenant, e.client)
	if _, err := e.create(ctx, e.tenant.ID, asset); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, "UPDATE content_keys SET provider = 'vault'"); err != nil {
		t.Fatal(err)
	}
	got, err := e.mgr.Get(ctx, e.tenant.ID, asset, keys.Original)
	wantCode(t, err, errs.InternalError)
	if !got.IsZero() {
		t.Fatal("a key of an unconfigured provider was returned")
	}
	if !errors.Is(err, kms.ErrNotConfigured) {
		t.Fatalf("want the cause to be ErrNotConfigured, got %v", err)
	}
}

// otherVersion answers Current with one version but wraps under another.
type otherVersion struct{ kms.Provider }

func (o otherVersion) Current(ctx context.Context) (kms.KeyRef, error) {
	ref, err := o.Provider.Current(ctx)
	ref.Version = "99"
	return ref, err
}

func TestWrapUnderUnexpectedVersionIsRefused(t *testing.T) {
	ctx := context.Background()
	reg, err := kms.NewRegistry(otherVersion{localProvider(t, 1)})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, localProvider(t, 1))
	m := contentkey.NewManager(e.pool, reg, newLogger(e.logs))
	asset := e.newAsset(t, e.tenant, e.client)
	err = db.Tx(ctx, e.pool, func(tx *db.Repos) error {
		_, err := m.Create(ctx, tx, e.tenant.ID, asset, keys.Original)
		return err
	})
	wantCode(t, err, errs.InternalError)
	if n := countRows(t, e.pool); n != 0 {
		t.Fatalf("a refused wrap left %d rows", n)
	}
}
