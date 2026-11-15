//go:build integration

package branding_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/branding"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }

type memStore struct {
	storage.Store
	mu      sync.Mutex
	objs    map[string][]byte
	failPut bool
}

func (m *memStore) Put(_ context.Context, key string, body io.Reader, _ int64, _ string) error {
	b, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPut {
		return storage.Sanitize("put", keys.Delivery, io.ErrUnexpectedEOF)
	}
	m.objs[key] = b
	return nil
}

func (m *memStore) DeleteBatch(_ context.Context, ks []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range ks {
		delete(m.objs, k)
	}
	return nil
}

func (m *memStore) has(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.objs[key]
	return ok
}

func (m *memStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.objs)
}

type rig struct {
	t     *testing.T
	svc   *branding.Service
	store *memStore
	repos *db.Repos
	a, b  db.Tenant
	ac    db.Client
	bc    db.Client
}

func newRig(t *testing.T) *rig {
	t.Helper()
	pool := dbtest.NewMigrated(t)
	r := &rig{t: t, store: &memStore{objs: map[string][]byte{}}, repos: db.New(pool)}
	svc, err := branding.New(branding.Deps{Pool: pool, Delivery: r.store})
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	ctx := context.Background()
	mk := func(name string) (db.Tenant, db.Client) {
		tn, err := r.repos.CreateTenant(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		cl, err := r.repos.CreateClient(ctx, tn.ID, name+"-client")
		if err != nil {
			t.Fatal(err)
		}
		return tn, cl
	}
	r.a, r.ac = mk("acme")
	r.b, r.bc = mk("other")
	return r
}

func pngOf(t *testing.T, w, h int, c color.NRGBA) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.R, c.G, c.B, c.A
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func actor() auth.Actor { return auth.Actor{} }

func wantCode(t *testing.T, err error, code errs.Code) {
	t.Helper()
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

func ptr[T any](v T) *T { return &v }

// asset makes an asset of the tenant in the given state and pins it to the tenant's logo as the
// pipeline does, in a transaction under the brand lock.
func (r *rig) pinned(tenant db.Tenant, client db.Client, state db.AssetState) (db.Asset, db.LogoPin) {
	r.t.Helper()
	ctx := context.Background()
	a, err := r.repos.CreateAsset(ctx, tenant.ID, client.ID, state)
	if err != nil {
		r.t.Fatal(err)
	}
	return a, r.pin(tenant.ID, a.ID)
}

func (r *rig) pin(tenant id.TenantID, asset id.AssetID) db.LogoPin {
	r.t.Helper()
	ctx := context.Background()
	tx, err := r.svc.Pool.Begin(ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	repos := db.New(tx)
	if err := repos.LockBrand(ctx, tenant); err != nil {
		r.t.Fatal(err)
	}
	pin, err := repos.PinAssetLogo(ctx, tenant, asset, r.svc.Now())
	if err != nil {
		r.t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		r.t.Fatal(err)
	}
	return pin
}

func TestPutGetUpdateDelete(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	_, err := r.svc.Get(ctx, r.a.ID)
	wantCode(t, err, errs.NotFound)

	up := pngOf(t, 120, 60, color.NRGBA{R: 200, G: 10, B: 10, A: 255})
	l, err := r.svc.Put(ctx, r.a.ID, actor(), up, branding.Placement{})
	if err != nil {
		t.Fatal(err)
	}
	if l.Corner != db.CornerBottomRight || l.OpacityPercent != 100 || !l.Enabled || l.Width != 120 || l.Height != 60 {
		t.Fatalf("defaults = %+v", l)
	}
	stored := r.store.objs[keys.BrandLogo(r.a.ID, l.ID)]
	if sum := sha256.Sum256(stored); !bytes.Equal(sum[:], l.SHA256) || len(stored) != l.SizeBytes || len(stored) == 0 {
		t.Fatal("the stored object is not what the row describes")
	}

	got, err := r.svc.Update(ctx, r.a.ID, actor(), branding.Placement{Corner: ptr(db.CornerTopLeft), Opacity: ptr(35)})
	if err != nil {
		t.Fatal(err)
	}
	if got.Corner != db.CornerTopLeft || got.OpacityPercent != 35 || !got.Enabled || got.ID != l.ID || !bytes.Equal(got.SHA256, l.SHA256) {
		t.Fatalf("after update = %+v", got)
	}
	got, err = r.svc.Update(ctx, r.a.ID, actor(), branding.Placement{Enabled: ptr(false)})
	if err != nil || got.Enabled || got.Corner != db.CornerTopLeft || got.OpacityPercent != 35 {
		t.Fatalf("disable = %+v, %v", got, err)
	}
	for _, bad := range []branding.Placement{{Corner: ptr("centre")}, {Opacity: ptr(9)}, {Opacity: ptr(101)}} {
		if _, err := r.svc.Update(ctx, r.a.ID, actor(), bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}

	if err := r.svc.Delete(ctx, r.a.ID, actor()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Get(ctx, r.a.ID); err == nil {
		t.Error("the logo is still there after delete")
	}
	if r.store.count() != 0 {
		t.Errorf("%d objects left after removing the logo", r.store.count())
	}
	wantCode(t, r.svc.Delete(ctx, r.a.ID, actor()), errs.NotFound)
	_, err = r.svc.Update(ctx, r.a.ID, actor(), branding.Placement{Corner: ptr(db.CornerTopLeft)})
	wantCode(t, err, errs.NotFound)
}

func TestHostileUploadsAreRefusedAndLeaveNothing(t *testing.T) {
	r := newRig(t)
	for name, data := range map[string][]byte{
		"text":  []byte("not a png"),
		"empty": nil,
		"big":   bytes.Repeat([]byte{1}, branding.MaxBytes+1),
	} {
		if _, err := r.svc.Put(context.Background(), r.a.ID, actor(), data, branding.Placement{}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := r.svc.Put(context.Background(), r.a.ID, actor(), pngOf(t, 64, 64, color.NRGBA{A: 255}), branding.Placement{Opacity: ptr(5)}); err == nil {
		t.Error("opacity 5 accepted")
	}
	if r.store.count() != 0 {
		t.Errorf("%d objects stored by refused uploads", r.store.count())
	}
	if _, err := r.svc.Get(context.Background(), r.a.ID); err == nil {
		t.Error("a refused upload became the logo")
	}
}

func TestAFailedStoreLeavesNoVersionAndKeepsTheOldLogo(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	first, err := r.svc.Put(ctx, r.a.ID, actor(), pngOf(t, 64, 64, color.NRGBA{R: 1, A: 255}), branding.Placement{})
	if err != nil {
		t.Fatal(err)
	}
	r.store.failPut = true
	if _, err := r.svc.Put(ctx, r.a.ID, actor(), pngOf(t, 64, 64, color.NRGBA{R: 2, A: 255}), branding.Placement{}); err == nil {
		t.Fatal("expected a storage error")
	}
	r.store.failPut = false
	cur, err := r.svc.Get(ctx, r.a.ID)
	if err != nil || cur.ID != first.ID || r.store.count() != 1 {
		t.Fatalf("current = %+v (%v), %d objects", cur, err, r.store.count())
	}
}

func TestANewUploadIsANewVersionAndTheOldOneIsRemoved(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	v1, err := r.svc.Put(ctx, r.a.ID, actor(), pngOf(t, 64, 64, color.NRGBA{R: 1, A: 255}), branding.Placement{})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := r.svc.Put(ctx, r.a.ID, actor(), pngOf(t, 64, 64, color.NRGBA{R: 2, A: 255}), branding.Placement{Corner: ptr(db.CornerTopRight)})
	if err != nil {
		t.Fatal(err)
	}
	if v1.ID == v2.ID || bytes.Equal(v1.SHA256, v2.SHA256) {
		t.Fatal("a new upload did not make a new version")
	}
	if r.store.has(keys.BrandLogo(r.a.ID, v1.ID)) || !r.store.has(keys.BrandLogo(r.a.ID, v2.ID)) || r.store.count() != 1 {
		t.Errorf("objects after the second upload: %d", r.store.count())
	}
	if ids, err := r.repos.ListUnusedLogoVersions(ctx, r.a.ID); err != nil || len(ids) != 0 {
		t.Errorf("unused versions left: %v %v", ids, err)
	}
}

// A version an asset in processing (or with its masked variant still to come) was pinned to stays
// until that asset is done; the next change then removes it.
func TestVersionsAnAssetStillNeedsAreKept(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	v1, err := r.svc.Put(ctx, r.a.ID, actor(), pngOf(t, 64, 64, color.NRGBA{R: 1, A: 255}), branding.Placement{})
	if err != nil {
		t.Fatal(err)
	}
	processing, pin := r.pinned(r.a, r.ac, db.AssetProcessing)
	if pin.VersionID != v1.ID {
		t.Fatalf("pinned %v, want %v", pin.VersionID, v1.ID)
	}
	maskPending, _ := r.pinned(r.a, r.ac, db.AssetReady)
	if _, err := r.svc.Pool.Exec(ctx, `UPDATE assets SET mask_faces = true, masking_state = 'pending' WHERE id = $1`, maskPending.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	finished, _ := r.pinned(r.a, r.ac, db.AssetReady)

	v2, err := r.svc.Put(ctx, r.a.ID, actor(), pngOf(t, 64, 64, color.NRGBA{R: 2, A: 255}), branding.Placement{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.store.has(keys.BrandLogo(r.a.ID, v1.ID)) {
		t.Fatal("version 1 was removed while assets still needed it")
	}
	// The retried job reads the same version back, not the tenant's new one.
	for _, a := range []db.Asset{processing, maskPending, finished} {
		if got := r.pin(r.a.ID, a.ID); got.VersionID != v1.ID {
			t.Errorf("asset %s: pin moved to %v", a.ID, got.VersionID)
		}
	}

	// The processing asset finishes; the masked variant is still pending, so the version stays.
	if _, err := r.svc.Pool.Exec(ctx, `UPDATE assets SET state = 'ready' WHERE id = $1`, processing.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Put(ctx, r.a.ID, actor(), pngOf(t, 64, 64, color.NRGBA{R: 3, A: 255}), branding.Placement{}); err != nil {
		t.Fatal(err)
	}
	if !r.store.has(keys.BrandLogo(r.a.ID, v1.ID)) {
		t.Fatal("version 1 was removed while a masked variant was still to be made")
	}
	if r.store.has(keys.BrandLogo(r.a.ID, v2.ID)) {
		t.Error("version 2, which no asset needs, was kept")
	}
	// Masking finishes: everything old goes with the next change, and a finished asset keeps its
	// pin (hash and placement) although the version is gone.
	if _, err := r.svc.Pool.Exec(ctx, `UPDATE assets SET masking_state = 'ready' WHERE id = $1`, maskPending.ID.UUID()); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.Delete(ctx, r.a.ID, actor()); err != nil {
		t.Fatal(err)
	}
	if r.store.count() != 0 {
		t.Errorf("%d objects left once nothing needed them", r.store.count())
	}
	pin2, ok, err := r.repos.GetAssetLogoPin(ctx, r.a.ID, finished.ID)
	if err != nil || !ok || pin2.VersionID != v1.ID || len(pin2.SHA256) != 32 {
		t.Errorf("the finished asset's pin = %+v %v %v", pin2, ok, err)
	}
}

// An asset takes the tenant's logo as it is when its first job starts, once; later changes do not
// reach it, and another tenant's logo never does.
func TestAnAssetKeepsWhatItWasPinnedTo(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	before, pinBefore := r.pinned(r.a, r.ac, db.AssetCommitted)
	if pinBefore.HasLogo() {
		t.Fatal("an asset got a logo the tenant never had")
	}
	v1, err := r.svc.Put(ctx, r.a.ID, actor(), pngOf(t, 64, 64, color.NRGBA{R: 1, A: 255}), branding.Placement{Corner: ptr(db.CornerTopLeft), Opacity: ptr(50)})
	if err != nil {
		t.Fatal(err)
	}
	if r.pin(r.a.ID, before.ID).HasLogo() {
		t.Error("a logo uploaded afterwards reached an asset that was already pinned")
	}
	_, p1 := r.pinned(r.a, r.ac, db.AssetCommitted)
	if p1.VersionID != v1.ID || p1.Corner != db.CornerTopLeft || p1.OpacityPercent != 50 || !bytes.Equal(p1.SHA256, v1.SHA256) {
		t.Fatalf("pin = %+v", p1)
	}

	// A placement change applies to the next asset only.
	if _, err := r.svc.Update(ctx, r.a.ID, actor(), branding.Placement{Corner: ptr(db.CornerBottomLeft), Opacity: ptr(90)}); err != nil {
		t.Fatal(err)
	}
	a2, p2 := r.pinned(r.a, r.ac, db.AssetCommitted)
	if p2.VersionID != v1.ID || p2.Corner != db.CornerBottomLeft || p2.OpacityPercent != 90 {
		t.Fatalf("pin after a placement change = %+v", p2)
	}
	// Disabled: no logo for new assets, the earlier ones keep theirs.
	if _, err := r.svc.Update(ctx, r.a.ID, actor(), branding.Placement{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, p3 := r.pinned(r.a, r.ac, db.AssetCommitted); p3.HasLogo() {
		t.Error("a disabled logo was pinned")
	}
	if got := r.pin(r.a.ID, a2.ID); got.Corner != db.CornerBottomLeft || !got.HasLogo() {
		t.Errorf("an earlier asset lost its logo: %+v", got)
	}

	// Tenant isolation: the other tenant has no logo, and cannot pin or read this tenant's assets.
	if _, pb := r.pinned(r.b, r.bc, db.AssetCommitted); pb.HasLogo() {
		t.Error("the other tenant's asset got this tenant's logo")
	}
	if _, err := r.repos.PinAssetLogo(ctx, r.b.ID, a2.ID, r.svc.Now()); err == nil {
		t.Error("a tenant pinned another tenant's asset")
	}
	if _, ok, err := r.repos.GetAssetLogoPin(ctx, r.b.ID, a2.ID); ok || err != nil {
		t.Errorf("a tenant read another tenant's pin: %v %v", ok, err)
	}
}

func TestTenantsHaveSeparateLogos(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	la, err := r.svc.Put(ctx, r.a.ID, actor(), pngOf(t, 64, 64, color.NRGBA{R: 1, A: 255}), branding.Placement{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Get(ctx, r.b.ID); err == nil {
		t.Fatal("tenant B sees tenant A's logo")
	}
	if _, err := r.svc.Update(ctx, r.b.ID, actor(), branding.Placement{Corner: ptr(db.CornerTopLeft)}); err == nil {
		t.Fatal("tenant B changed tenant A's logo")
	}
	if err := r.svc.Delete(ctx, r.b.ID, actor()); err == nil {
		t.Fatal("tenant B deleted tenant A's logo")
	}
	lb, err := r.svc.Put(ctx, r.b.ID, actor(), pngOf(t, 64, 64, color.NRGBA{R: 1, A: 255}), branding.Placement{})
	if err != nil {
		t.Fatal(err)
	}
	// The same picture is a separate version under a separate prefix, and B's removal leaves A's.
	if la.ID == lb.ID || !r.store.has(keys.BrandLogo(r.a.ID, la.ID)) || !r.store.has(keys.BrandLogo(r.b.ID, lb.ID)) {
		t.Fatal("the two tenants share a version or an object")
	}
	if err := r.svc.Delete(ctx, r.b.ID, actor()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Get(ctx, r.a.ID); err != nil || !r.store.has(keys.BrandLogo(r.a.ID, la.ID)) {
		t.Fatalf("tenant A lost its logo: %v", err)
	}
}
