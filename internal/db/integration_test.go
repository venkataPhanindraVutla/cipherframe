//go:build integration

package db_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

const defaultPGImage = "postgres:18.6"

var (
	adminURL string // connection URL of the container's maintenance database
	dbCount  atomic.Int64
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	image := os.Getenv("CIPHERFRAME_TEST_PG_IMAGE")
	if image == "" {
		image = defaultPGImage
	}
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, image,
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot start the test Postgres container:", err)
		return 1
	}
	defer func() { _ = testcontainers.TerminateContainer(ctr) }()
	adminURL, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read the container connection string:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "integration tests run against", image)
	return m.Run()
}

// newDatabase creates an empty database inside the container and returns a pool on it.
func newDatabase(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	defer admin.Close()
	name := fmt.Sprintf("t%d", dbCount.Add(1))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, name
}

// newMigrated returns repositories over a freshly migrated database.
func newMigrated(t *testing.T) (*db.Repos, *pgxpool.Pool) {
	t.Helper()
	pool, _ := newDatabase(t)
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.New(pool), pool
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

func micro(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

type fixture struct {
	tenant db.Tenant
	client db.Client
}

func newFixture(t *testing.T, r *db.Repos, name string) fixture {
	t.Helper()
	ctx := context.Background()
	tn, err := r.CreateTenant(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := r.CreateClient(ctx, tn.ID, name+"-client")
	if err != nil {
		t.Fatal(err)
	}
	return fixture{tenant: tn, client: cl}
}

func newKey(t *testing.T, r *db.Repos, clientID id.ClientID, prefix string) db.APIKey {
	t.Helper()
	k, err := r.CreateAPIKey(context.Background(), db.NewAPIKey{
		ClientID:      clientID,
		Name:          "key " + prefix,
		Prefix:        prefix,
		SecretHash:    bytes.Repeat([]byte{1}, 32),
		PepperVersion: 1,
		Scopes:        []db.Scope{db.ScopeAssetsRead, db.ScopeAssetsWrite},
	})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestMigrateFromEmptyAndIdempotent(t *testing.T) {
	ctx := context.Background()
	pool, _ := newDatabase(t)

	for i := 0; i < 2; i++ {
		if err := db.Migrate(ctx, pool); err != nil {
			t.Fatalf("migrate run %d: %v", i+1, err)
		}
	}
	for _, table := range []string{"tenants", "clients", "api_keys", "assets", "audit_events", "content_keys", "external_tasks", "upload_tokens", "upload_parts", "asset_artifacts", "playback_settings", "playback_sessions", "river_job", "river_migration"} {
		var n int
		err := pool.QueryRow(ctx,
			"SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1",
			table).Scan(&n)
		if err != nil || n != 1 {
			t.Errorf("table %s missing (n=%d, err=%v)", table, n, err)
		}
	}
	var applied int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM goose_db_version WHERE version_id > 0").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 6 {
		t.Fatalf("applied migrations = %d, want 6", applied)
	}
	// River's schema is applied by the same call and is not re-applied by a further run.
	var riverVersions int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM river_migration").Scan(&riverVersions); err != nil || riverVersions == 0 {
		t.Fatalf("river migrations recorded = %d, err = %v", riverVersions, err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("third migrate: %v", err)
	}
	var after int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM river_migration").Scan(&after); err != nil || after != riverVersions {
		t.Fatalf("river migrations after a further run = %d, want %d (err %v)", after, riverVersions, err)
	}
}

func TestMigrateConcurrently(t *testing.T) {
	ctx := context.Background()
	pool, _ := newDatabase(t)
	var wg sync.WaitGroup
	errc := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errc <- db.Migrate(ctx, pool)
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil {
			t.Fatalf("concurrent migrate: %v", err)
		}
	}
}

func TestCheckServerVersion(t *testing.T) {
	pool, _ := newDatabase(t)
	if err := db.CheckServerVersion(context.Background(), pool); err != nil {
		t.Fatalf("supported server rejected: %v", err)
	}
}

func TestOpen(t *testing.T) {
	_, name := newDatabase(t)
	u := adminURL[:len(adminURL)-len("postgres?sslmode=disable")] + name + "?sslmode=disable"
	pool, err := db.Open(context.Background(), &config.Config{DatabaseURL: config.NewSecret(u)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pool.Close()
}

func TestTenantsAndClients(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)

	tn, err := r.CreateTenant(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if tn.ID.IsZero() || tn.Name != "acme" || tn.DisabledAt != nil || tn.CreatedAt.IsZero() {
		t.Fatalf("unexpected tenant: %+v", tn)
	}
	got, err := r.GetTenant(ctx, tn.ID)
	if err != nil || got != tn {
		t.Fatalf("GetTenant = %+v, %v; want %+v", got, err, tn)
	}
	_, err = r.GetTenant(ctx, id.New[id.TenantKind]())
	wantCode(t, err, errs.NotFound)

	c1, err := r.CreateClient(ctx, tn.ID, "web")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := r.CreateClient(ctx, tn.ID, "mobile")
	if err != nil {
		t.Fatal(err)
	}
	if c1.TenantID != tn.ID {
		t.Fatalf("client tenant = %v, want %v", c1.TenantID, tn.ID)
	}
	gc, err := r.GetClient(ctx, tn.ID, c1.ID)
	if err != nil || gc != c1 {
		t.Fatalf("GetClient = %+v, %v; want %+v", gc, err, c1)
	}
	list, err := r.ListClients(ctx, tn.ID, 10, 0)
	if err != nil || len(list) != 2 || list[0].ID != c1.ID || list[1].ID != c2.ID {
		t.Fatalf("ListClients = %+v, %v", list, err)
	}
	page, err := r.ListClients(ctx, tn.ID, 1, 1)
	if err != nil || len(page) != 1 || page[0].ID != c2.ID {
		t.Fatalf("ListClients page = %+v, %v", page, err)
	}

	// A client under an unknown tenant is a foreign key violation: internal_error, never not_found.
	_, err = r.CreateClient(ctx, id.New[id.TenantKind](), "orphan")
	wantCode(t, err, errs.InternalError)
}

func TestAPIKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")

	k := newKey(t, r, f.client.ID, "abc123")
	if k.ID.IsZero() || k.ClientID != f.client.ID || k.Prefix != "abc123" || k.Previous != nil ||
		k.RotatedAt != nil || k.RevokedAt != nil || k.LastUsedAt != nil || k.PepperVersion != 1 {
		t.Fatalf("unexpected key: %+v", k)
	}
	if len(k.Scopes) != 2 || k.Scopes[0] != db.ScopeAssetsRead {
		t.Fatalf("scopes = %v", k.Scopes)
	}

	byID, err := r.GetAPIKey(ctx, f.tenant.ID, k.ID)
	if err != nil || byID.Prefix != k.Prefix || byID.ID != k.ID {
		t.Fatalf("GetAPIKey = %+v, %v", byID, err)
	}

	auth, err := r.GetActiveAPIKeyByPrefix(ctx, "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if auth.ID != k.ID || auth.TenantID != f.tenant.ID || auth.ClientID != f.client.ID ||
		auth.ClientDisabledAt != nil || auth.TenantDisabledAt != nil || !bytes.Equal(auth.SecretHash, k.SecretHash) {
		t.Fatalf("unexpected auth key: %+v", auth)
	}
	_, err = r.GetActiveAPIKeyByPrefix(ctx, "nope")
	wantCode(t, err, errs.NotFound)

	used := micro(time.Now())
	if err := r.TouchAPIKeyLastUsed(ctx, k.ID, used); err != nil {
		t.Fatal(err)
	}
	byID, err = r.GetAPIKey(ctx, f.tenant.ID, k.ID)
	if err != nil || byID.LastUsedAt == nil || !byID.LastUsedAt.Equal(used) {
		t.Fatalf("last_used_at = %v, %v; want %v", byID.LastUsedAt, err, used)
	}

	// Revocation hides the key from the authentication lookup but not from management reads.
	at := micro(time.Now())
	rev, err := r.RevokeAPIKey(ctx, f.tenant.ID, k.ID, at)
	if err != nil || rev.RevokedAt == nil || !rev.RevokedAt.Equal(at) {
		t.Fatalf("RevokeAPIKey = %+v, %v", rev, err)
	}
	_, err = r.GetActiveAPIKeyByPrefix(ctx, "abc123")
	wantCode(t, err, errs.NotFound)
	again, err := r.RevokeAPIKey(ctx, f.tenant.ID, k.ID, at.Add(time.Hour))
	if err != nil || !again.RevokedAt.Equal(at) {
		t.Fatalf("revoke must be idempotent and keep the first time: %+v, %v", again, err)
	}
	if _, err := r.GetAPIKey(ctx, f.tenant.ID, k.ID); err != nil {
		t.Fatalf("revoked key should remain readable for management: %v", err)
	}
	// A revoked key cannot be rotated.
	_, err = r.RotateAPIKey(ctx, f.tenant.ID, k.ID, db.RotateParams{
		NewSecretHash: []byte{9}, NewPepperVersion: 2, RotatedAt: at, PreviousValidUntil: at,
	})
	wantCode(t, err, errs.NotFound)
}

func TestAPIKeyDisabledMarkers(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	newKey(t, r, f.client.ID, "dis001")
	if _, err := pool.Exec(ctx, "UPDATE clients SET disabled_at = now() WHERE id = $1", f.client.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE tenants SET disabled_at = now() WHERE id = $1", f.tenant.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	auth, err := r.GetActiveAPIKeyByPrefix(ctx, "dis001")
	if err != nil {
		t.Fatal(err)
	}
	if auth.ClientDisabledAt == nil || auth.TenantDisabledAt == nil {
		t.Fatalf("disabled markers missing: %+v", auth)
	}
}

func TestPrefixConflict(t *testing.T) {
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	newKey(t, r, f.client.ID, "dup001")
	_, err := r.CreateAPIKey(context.Background(), db.NewAPIKey{
		ClientID: f.client.ID, Name: "again", Prefix: "dup001",
		SecretHash: []byte{2}, PepperVersion: 1, Scopes: []db.Scope{db.ScopeAdmin},
	})
	wantCode(t, err, errs.Conflict)
}

func TestRotationPreservesOwnership(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")

	key := newKey(t, r, f.client.ID, "rot001")
	asset, err := r.CreateAsset(ctx, f.tenant.ID, f.client.ID, db.AssetCreated)
	if err != nil {
		t.Fatal(err)
	}
	var events []db.AuditEvent
	for i := 0; i < 3; i++ {
		ev, err := r.InsertAuditEvent(ctx, db.NewAuditEvent{
			TenantID: f.tenant.ID, ClientID: f.client.ID, APIKeyID: key.ID,
			Action: "asset.create", Target: asset.ID.String(), RequestID: fmt.Sprintf("req-%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, ev)
	}

	now := micro(time.Now())
	newHash := bytes.Repeat([]byte{7}, 32)
	rotated, err := r.RotateAPIKey(ctx, f.tenant.ID, key.ID, db.RotateParams{
		NewSecretHash: newHash, NewPepperVersion: 2, RotatedAt: now, PreviousValidUntil: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	if rotated.ID != key.ID || rotated.Prefix != key.Prefix || rotated.ClientID != key.ClientID || rotated.Name != key.Name {
		t.Fatalf("identity changed on rotation: before %+v after %+v", key, rotated)
	}
	if !bytes.Equal(rotated.SecretHash, newHash) || rotated.PepperVersion != 2 {
		t.Fatalf("new secret not stored: %+v", rotated)
	}
	if rotated.Previous == nil || !bytes.Equal(rotated.Previous.Hash, key.SecretHash) ||
		rotated.Previous.PepperVersion != 1 || !rotated.Previous.ValidUntil.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("previous secret wrong: %+v", rotated.Previous)
	}
	if rotated.RotatedAt == nil || !rotated.RotatedAt.Equal(now) {
		t.Fatalf("rotated_at = %v", rotated.RotatedAt)
	}
	if len(rotated.Scopes) != len(key.Scopes) {
		t.Fatalf("scopes changed: %v", rotated.Scopes)
	}

	// The prefix lookup now sees the new hash on the same key and owner.
	auth, err := r.GetActiveAPIKeyByPrefix(ctx, "rot001")
	if err != nil || auth.ID != key.ID || auth.TenantID != f.tenant.ID || !bytes.Equal(auth.SecretHash, newHash) || auth.Previous == nil {
		t.Fatalf("lookup after rotation: %+v, %v", auth, err)
	}

	// Assets and audit rows are untouched.
	after, err := r.GetAsset(ctx, f.tenant.ID, asset.ID)
	if err != nil || !reflect.DeepEqual(after, asset) {
		t.Fatalf("asset changed by rotation: %+v vs %+v (%v)", after, asset, err)
	}
	if after.CreatedByClientID != f.client.ID {
		t.Fatal("asset ownership moved")
	}
	list, err := r.ListAuditEvents(ctx, f.tenant.ID, nil, 100)
	if err != nil || len(list) != len(events) {
		t.Fatalf("audit rows after rotation: %d, %v", len(list), err)
	}
	for i := range events {
		if list[i] != events[i] || list[i].APIKeyID != key.ID {
			t.Fatalf("audit row %d changed: %+v vs %+v", i, list[i], events[i])
		}
	}

	// Rotating again moves the (new) hash to previous_*.
	second, err := r.RotateAPIKey(ctx, f.tenant.ID, key.ID, db.RotateParams{
		NewSecretHash: bytes.Repeat([]byte{8}, 32), NewPepperVersion: 3, RotatedAt: now.Add(time.Hour), PreviousValidUntil: now.Add(time.Hour),
	})
	if err != nil || second.Previous == nil || !bytes.Equal(second.Previous.Hash, newHash) || second.Previous.PepperVersion != 2 {
		t.Fatalf("second rotation: %+v, %v", second, err)
	}
}

func TestRotationRejectsInvalidParams(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	k := newKey(t, r, f.client.ID, "rot002")
	now := micro(time.Now())
	_, err := r.RotateAPIKey(ctx, f.tenant.ID, k.ID, db.RotateParams{
		NewSecretHash: nil, NewPepperVersion: 2, RotatedAt: now, PreviousValidUntil: now,
	})
	wantCode(t, err, errs.InvalidRequest)
	_, err = r.RotateAPIKey(ctx, f.tenant.ID, k.ID, db.RotateParams{
		NewSecretHash: []byte{1}, NewPepperVersion: 2, RotatedAt: now, PreviousValidUntil: now.Add(-time.Second),
	})
	wantCode(t, err, errs.InvalidRequest)
}

func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	a := newFixture(t, r, "tenant-a")
	b := newFixture(t, r, "tenant-b")

	asset, err := r.CreateAsset(ctx, a.tenant.ID, a.client.ID, db.AssetCreated)
	if err != nil {
		t.Fatal(err)
	}
	key := newKey(t, r, a.client.ID, "iso001")
	if _, err := r.InsertAuditEvent(ctx, db.NewAuditEvent{TenantID: a.tenant.ID, Action: "x"}); err != nil {
		t.Fatal(err)
	}

	if got, err := r.GetAsset(ctx, a.tenant.ID, asset.ID); err != nil || got.ID != asset.ID {
		t.Fatalf("owner cannot read its asset: %v", err)
	}
	_, err = r.GetAsset(ctx, b.tenant.ID, asset.ID)
	wantCode(t, err, errs.NotFound)
	_, err = r.GetClient(ctx, b.tenant.ID, a.client.ID)
	wantCode(t, err, errs.NotFound)
	_, err = r.GetAPIKey(ctx, b.tenant.ID, key.ID)
	wantCode(t, err, errs.NotFound)
	_, err = r.RotateAPIKey(ctx, b.tenant.ID, key.ID, db.RotateParams{
		NewSecretHash: []byte{1}, NewPepperVersion: 2, RotatedAt: time.Now(), PreviousValidUntil: time.Now(),
	})
	wantCode(t, err, errs.NotFound)
	_, err = r.RevokeAPIKey(ctx, b.tenant.ID, key.ID, time.Now())
	wantCode(t, err, errs.NotFound)

	// Tenant B cannot create an asset on behalf of tenant A's client.
	_, err = r.CreateAsset(ctx, b.tenant.ID, a.client.ID, db.AssetCreated)
	wantCode(t, err, errs.NotFound)

	clients, err := r.ListClients(ctx, b.tenant.ID, 10, 0)
	if err != nil || len(clients) != 1 || clients[0].ID != b.client.ID {
		t.Fatalf("tenant B client list leaks: %+v, %v", clients, err)
	}
	events, err := r.ListAuditEvents(ctx, b.tenant.ID, nil, 10)
	if err != nil || len(events) != 0 {
		t.Fatalf("tenant B audit list leaks: %+v, %v", events, err)
	}

	// The failed attempts changed nothing for tenant A.
	if k, err := r.GetActiveAPIKeyByPrefix(ctx, "iso001"); err != nil || k.RotatedAt != nil || k.RevokedAt != nil {
		t.Fatalf("tenant A key was modified: %+v, %v", k, err)
	}
}

func TestAssets(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	a, err := r.CreateAsset(ctx, f.tenant.ID, f.client.ID, db.AssetCreated)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID.IsZero() || a.TenantID != f.tenant.ID || a.CreatedByClientID != f.client.ID || a.State != db.AssetCreated {
		t.Fatalf("unexpected asset: %+v", a)
	}
	got, err := r.GetAsset(ctx, f.tenant.ID, a.ID)
	if err != nil || !reflect.DeepEqual(got, a) {
		t.Fatalf("GetAsset = %+v, %v; want %+v", got, err, a)
	}
	_, err = r.GetAsset(ctx, f.tenant.ID, id.New[id.AssetKind]())
	wantCode(t, err, errs.NotFound)
}

func TestAuditEvents(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	key := newKey(t, r, f.client.ID, "aud001")

	e1, err := r.InsertAuditEvent(ctx, db.NewAuditEvent{
		TenantID: f.tenant.ID, ClientID: f.client.ID, APIKeyID: key.ID, Action: "key.rotate", Target: key.ID.String(), RequestID: "req-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	e2, err := r.InsertAuditEvent(ctx, db.NewAuditEvent{TenantID: f.tenant.ID, Action: "tenant.touch"})
	if err != nil {
		t.Fatal(err)
	}
	if e2.ClientID != (id.ClientID{}) || e2.APIKeyID != (id.APIKeyID{}) || e2.Target != "" || e2.RequestID != "" {
		t.Fatalf("optional fields should be empty: %+v", e2)
	}

	all, err := r.ListAuditEvents(ctx, f.tenant.ID, nil, 10)
	if err != nil || len(all) != 2 || all[0] != e1 || all[1] != e2 {
		t.Fatalf("list = %+v, %v", all, err)
	}
	first, err := r.ListAuditEvents(ctx, f.tenant.ID, nil, 1)
	if err != nil || len(first) != 1 || first[0].ID != e1.ID {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	next, err := r.ListAuditEvents(ctx, f.tenant.ID, &db.AuditCursor{CreatedAt: first[0].CreatedAt, ID: first[0].ID}, 10)
	if err != nil || len(next) != 1 || next[0].ID != e2.ID {
		t.Fatalf("next page = %+v, %v", next, err)
	}

	// No foreign keys: rows survive deletion of the things they describe, and may reference
	// tenants that never existed.
	ghost := id.New[id.TenantKind]()
	if _, err := r.InsertAuditEvent(ctx, db.NewAuditEvent{TenantID: ghost, ClientID: id.New[id.ClientKind](), APIKeyID: id.New[id.APIKeyKind](), Action: "ghost"}); err != nil {
		t.Fatalf("audit insert must not need parent rows: %v", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM api_keys WHERE id = $1", key.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	after, err := r.ListAuditEvents(ctx, f.tenant.ID, nil, 10)
	if err != nil || len(after) != 2 {
		t.Fatalf("audit rows must survive key deletion: %d, %v", len(after), err)
	}
	var fks int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM information_schema.table_constraints WHERE table_name = 'audit_events' AND constraint_type = 'FOREIGN KEY'").Scan(&fks); err != nil || fks != 0 {
		t.Fatalf("audit_events has %d foreign keys, %v", fks, err)
	}
}

func TestCountAPIKeysByPepperVersion(t *testing.T) {
	ctx := context.Background()
	r, _ := newMigrated(t)
	f := newFixture(t, r, "acme")
	now := micro(time.Now())

	k1 := newKey(t, r, f.client.ID, "cnt001") // version 1
	newKey(t, r, f.client.ID, "cnt002")       // version 1
	k3 := newKey(t, r, f.client.ID, "cnt003") // version 1, revoked below

	if _, err := r.RevokeAPIKey(ctx, f.tenant.ID, k3.ID, now); err != nil {
		t.Fatal(err)
	}
	// k1 rotates to version 2 with a 10 minute overlap: it still references version 1.
	if _, err := r.RotateAPIKey(ctx, f.tenant.ID, k1.ID, db.RotateParams{
		NewSecretHash: []byte{5}, NewPepperVersion: 2, RotatedAt: now, PreviousValidUntil: now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	got, err := r.CountAPIKeysByPepperVersion(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1] != 2 || got[2] != 1 { // cnt002 + k1's previous hash; k1 current
		t.Fatalf("counts during overlap = %v, want map[1:2 2:1]", got)
	}
	got, err = r.CountAPIKeysByPepperVersion(ctx, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1] != 1 || got[2] != 1 {
		t.Fatalf("counts after overlap = %v, want map[1:1 2:1]", got)
	}
}

func TestConstraints(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)
	f := newFixture(t, r, "acme")
	cid := f.client.ID.UUID()

	insertKey := func(prefix string, scopes []string, hash []byte, ver *int32, until *time.Time) error {
		_, err := pool.Exec(ctx, `INSERT INTO api_keys
			(id, client_id, name, prefix, secret_hash, pepper_version, scopes,
			 previous_secret_hash, previous_pepper_version, previous_valid_until)
			VALUES ($1, $2, 'n', $3, '\x01', 1, $4, $5, $6, $7)`,
			id.New[id.APIKeyKind]().UUID(), cid, prefix, scopes, hash, ver, until)
		return err
	}
	pgCode := func(err error) string {
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			return pe.Code
		}
		return ""
	}

	one, ts := int32(1), time.Now()
	if err := insertKey("ok0001", []string{"assets:read", "admin"}, nil, nil, nil); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if err := insertKey("ok0002", []string{}, []byte{1}, &one, &ts); err != nil {
		t.Fatalf("fully set previous_* rejected: %v", err)
	}
	if code := pgCode(insertKey("bad001", []string{"assets:read", "root"}, nil, nil, nil)); code != "23514" {
		t.Errorf("bad scope: pg code %q, want 23514", code)
	}
	if code := pgCode(insertKey("bad002", []string{"Assets:Read"}, nil, nil, nil)); code != "23514" {
		t.Errorf("wrong-case scope: pg code %q, want 23514", code)
	}
	partials := []struct {
		name string
		hash []byte
		ver  *int32
		at   *time.Time
	}{
		{"hash only", []byte{1}, nil, nil},
		{"version only", nil, &one, nil},
		{"valid_until only", nil, nil, &ts},
		{"hash and version", []byte{1}, &one, nil},
		{"version and valid_until", nil, &one, &ts},
	}
	for i, p := range partials {
		if code := pgCode(insertKey(fmt.Sprintf("part%02d", i), []string{"admin"}, p.hash, p.ver, p.at)); code != "23514" {
			t.Errorf("partial previous_* (%s): pg code %q, want 23514", p.name, code)
		}
	}

	// Asset state is a closed set.
	_, err := pool.Exec(ctx, `INSERT INTO assets (id, tenant_id, created_by_client_id, state) VALUES ($1, $2, $3, 'bogus')`,
		id.New[id.AssetKind]().UUID(), f.tenant.ID.UUID(), cid)
	if pgCode(err) != "23514" {
		t.Errorf("bad asset state: pg code %q, want 23514", pgCode(err))
	}
}

func TestTx(t *testing.T) {
	ctx := context.Background()
	r, pool := newMigrated(t)

	var created db.Tenant
	err := db.Tx(ctx, pool, func(tx *db.Repos) error {
		var err error
		created, err = tx.CreateTenant(ctx, "committed")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetTenant(ctx, created.ID); err != nil {
		t.Fatalf("committed tenant missing: %v", err)
	}

	var rolled db.Tenant
	sentinel := errors.New("stop")
	err = db.Tx(ctx, pool, func(tx *db.Repos) error {
		var err error
		rolled, err = tx.CreateTenant(ctx, "rolled-back")
		if err != nil {
			return err
		}
		if _, err := tx.GetTenant(ctx, rolled.ID); err != nil {
			return fmt.Errorf("tenant invisible inside its own tx: %w", err)
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Tx error = %v, want the callback's error", err)
	}
	_, err = r.GetTenant(ctx, rolled.ID)
	wantCode(t, err, errs.NotFound)

	// A panic rolls back and propagates.
	var panicked db.Tenant
	func() {
		defer func() { _ = recover() }()
		_ = db.Tx(ctx, pool, func(tx *db.Repos) error {
			panicked, _ = tx.CreateTenant(ctx, "panicked")
			panic("boom")
		})
	}()
	_, err = r.GetTenant(ctx, panicked.ID)
	wantCode(t, err, errs.NotFound)

	// A unique violation inside a transaction maps to conflict.
	f := newFixture(t, r, "acme")
	newKey(t, r, f.client.ID, "tx0001")
	err = db.Tx(ctx, pool, func(tx *db.Repos) error {
		_, err := tx.CreateAPIKey(ctx, db.NewAPIKey{
			ClientID: f.client.ID, Name: "n", Prefix: "tx0001", SecretHash: []byte{1}, PepperVersion: 1, Scopes: []db.Scope{db.ScopeAdmin},
		})
		return err
	})
	wantCode(t, err, errs.Conflict)
}

func TestClosedPoolMapsToUnavailable(t *testing.T) {
	r, pool := newMigrated(t)
	pool.Close()
	_, err := r.GetTenant(context.Background(), id.New[id.TenantKind]())
	var e *errs.Error
	if !errors.As(err, &e) || e.Code == errs.NotFound {
		t.Fatalf("closed pool error = %v; must not be not_found", err)
	}
	wantCode(t, err, errs.DependencyUnavailable)
}

func TestCancelledContextMapsToTimeout(t *testing.T) {
	r, _ := newMigrated(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	_, err := r.GetTenant(ctx, id.New[id.TenantKind]())
	wantCode(t, err, errs.Timeout)
}

// TestMigrateConcurrentlySmallPool reproduces CI runners with two CPUs, where pgxpool defaults to
// four connections: four concurrent Migrate calls must not deadlock on pool exhaustion.
func TestMigrateConcurrentlySmallPool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	base, _ := newDatabase(t)
	cfg := base.Config().Copy()
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var wg sync.WaitGroup
	errc := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errc <- db.Migrate(ctx, pool)
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil {
			t.Fatalf("concurrent migrate on a 4-connection pool: %v", err)
		}
	}
}
