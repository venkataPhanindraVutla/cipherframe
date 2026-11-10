//go:build integration

package auth_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
)

func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }

type peppers map[int]config.Secret

func (p peppers) Get(v int) (config.Secret, bool) { s, ok := p[v]; return s, ok }
func (p peppers) Current() (int, config.Secret) {
	best := 0
	for v := range p {
		best = max(best, v)
	}
	return best, p[best]
}

func TestBootstrapIsAtomic(t *testing.T) {
	pool := dbtest.NewMigrated(t)
	ctx := context.Background()
	p := peppers{1: config.NewSecret(strings.Repeat("a", 32))}
	m := auth.NewManager(pool, p, nil)

	// An invalid client name must leave no tenant behind.
	if _, err := m.Bootstrap(ctx, "acme", ""); err == nil {
		t.Fatal("expected an error")
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM tenants").Scan(&n); err != nil || n != 0 {
		t.Fatalf("tenants = %d, %v", n, err)
	}

	res, err := m.Bootstrap(ctx, "acme", "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Key.Scopes) != 5 || res.Key.PepperVersion != 1 {
		t.Fatalf("bootstrap key = %+v", res.Key)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id = $1", res.Tenant.ID.UUID()).Scan(&n); err != nil || n != 3 {
		t.Fatalf("audit rows = %d, %v", n, err)
	}
}

func TestCheckPeppersAgainstDatabase(t *testing.T) {
	pool := dbtest.NewMigrated(t)
	ctx := context.Background()
	repos := db.New(pool)
	old := peppers{1: config.NewSecret(strings.Repeat("a", 32))}
	if _, err := auth.NewManager(pool, old, nil).Bootstrap(ctx, "acme", "main"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	if err := auth.CheckPeppers(ctx, repos, old, now); err != nil {
		t.Fatalf("configured pepper: %v", err)
	}
	// Only version 2 configured while a key still uses version 1: refuse, naming the number.
	err := auth.CheckPeppers(ctx, repos, peppers{2: config.NewSecret(strings.Repeat("b", 32))}, now)
	if err == nil || !strings.Contains(err.Error(), "version(s) 1") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("a", 32)) {
		t.Fatal("pepper value in the error")
	}

	// After pepper 2 becomes current, new keys use it and usage reports both versions.
	both := peppers{1: old[1], 2: config.NewSecret(strings.Repeat("b", 32))}
	res, err := auth.NewManager(pool, both, nil).Bootstrap(ctx, "beta", "main")
	if err != nil || res.Key.PepperVersion != 2 {
		t.Fatalf("new key pepper version: %+v %v", res.Key, err)
	}
	usage, err := repos.CountAPIKeysByPepperVersion(ctx, now)
	if err != nil || usage[1] != 1 || usage[2] != 1 {
		t.Fatalf("usage = %v, %v", usage, err)
	}
}
