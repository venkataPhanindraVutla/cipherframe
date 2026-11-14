package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/timestamp"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/timestamp/tsatest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
)

type fakeRepo struct {
	m      *db.AssetManifest
	stored []db.ManifestTimestamp
	accept bool // SetManifestTimestamp result
}

func (f *fakeRepo) GetManifest(context.Context, id.AssetID) (db.AssetManifest, error) {
	if f.m == nil {
		return db.AssetManifest{}, errs.New(errs.NotFound, "none")
	}
	return *f.m, nil
}

func (f *fakeRepo) SetManifestTimestamp(_ context.Context, _ id.AssetID, _ []byte, ts db.ManifestTimestamp) (bool, error) {
	f.stored = append(f.stored, ts)
	return f.accept, nil
}

type fakeStamper struct {
	err   error
	calls int
}

func (s *fakeStamper) Stamp(_ context.Context, d [sha256.Size]byte) (*timestamp.Token, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &timestamp.Token{DER: append([]byte("test-fixture-token-"), d[:2]...), GenTime: time.Unix(1700000000, 0).UTC()}, nil
}

func manifestRow(t *testing.T, payload string) *db.AssetManifest {
	t.Helper()
	enc, err := (&dsse.Envelope{PayloadType: "t", Payload: []byte(payload), Signatures: []dsse.Signature{{KeyID: "k", Sig: []byte("s")}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(payload))
	return &db.AssetManifest{PayloadSHA256: sum[:], Envelope: enc}
}

func run(t *testing.T, repo *fakeRepo, st Stamper, args Args, attempt, max int) (string, error) {
	t.Helper()
	var logs bytes.Buffer
	d := Deps{
		Repo: repo, Stamper: st, TSAURL: "https://tsa.example/tsr", Timeout: time.Second,
		Log: slog.New(slog.NewTextHandler(&logs, nil)),
	}
	err := d.handle(context.Background(), jobs.Job[Args]{Args: args, Attempt: attempt, MaxAttempts: max})
	return logs.String(), err
}

func argsFor(m *db.AssetManifest) Args {
	a := Args{TenantID: id.New[id.TenantKind](), AssetID: id.New[id.AssetKind]()}
	if m != nil {
		a.PayloadSHA256 = hexOf(m.PayloadSHA256)
	}
	return a
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func TestHandleStoresToken(t *testing.T) {
	m := manifestRow(t, "test-fixture-payload")
	repo, st := &fakeRepo{m: m, accept: true}, &fakeStamper{}
	logs, err := run(t, repo, st, argsFor(m), 1, 10)
	if err != nil || len(repo.stored) != 1 || repo.stored[0].TSAURL != "https://tsa.example/tsr" || !strings.Contains(logs, "manifest anchored") {
		t.Fatalf("err %v stored %+v logs %s", err, repo.stored, logs)
	}
}

func TestHandleSkips(t *testing.T) {
	m := manifestRow(t, "test-fixture-payload")
	with := func(f func(*db.AssetManifest)) *db.AssetManifest { c := *m; f(&c); return &c }
	forged := bytes.Repeat([]byte{1}, 32)
	for name, tc := range map[string]struct {
		repo   *fakeRepo
		args   Args
		cancel bool // the job is cancelled rather than finished
	}{
		"manifest gone":    {&fakeRepo{}, argsFor(m), false},
		"re-signed since":  {&fakeRepo{m: m}, argsFor(manifestRow(t, "test-fixture-newer")), false},
		"already anchored": {&fakeRepo{m: with(func(c *db.AssetManifest) { c.Timestamp = &db.ManifestTimestamp{} })}, argsFor(m), false},
		"no asset":         {&fakeRepo{m: m}, Args{}, true},
		"digest forged": {
			&fakeRepo{m: with(func(c *db.AssetManifest) { c.PayloadSHA256 = forged })},
			Args{TenantID: id.New[id.TenantKind](), AssetID: id.New[id.AssetKind](), PayloadSHA256: hexOf(forged)},
			true,
		},
	} {
		st := &fakeStamper{}
		_, err := run(t, tc.repo, st, tc.args, 1, 10)
		if st.calls != 0 || len(tc.repo.stored) != 0 {
			t.Errorf("%s: the authority was asked or a token stored", name)
		}
		if tc.cancel == (err == nil) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestHandleRetriesThenGivesUp(t *testing.T) {
	m := manifestRow(t, "test-fixture-payload")
	repo, st := &fakeRepo{m: m, accept: true}, &fakeStamper{err: errors.New("boom")}
	logs, err := run(t, repo, st, argsFor(m), 1, 3)
	if err == nil || !strings.Contains(logs, "will retry") || len(repo.stored) != 0 {
		t.Fatalf("first attempt: %v %s", err, logs)
	}
	logs, err = run(t, repo, st, argsFor(m), 3, 3)
	if err == nil || !strings.Contains(logs, "gave up") || !strings.Contains(logs, "level=ERROR") {
		t.Fatalf("last attempt: %v %s", err, logs)
	}
}

func TestHandleDropsTokenOfReplacedManifest(t *testing.T) {
	m := manifestRow(t, "test-fixture-payload")
	repo := &fakeRepo{m: m, accept: false}
	logs, err := run(t, repo, &fakeStamper{}, argsFor(m), 1, 10)
	if err != nil || !strings.Contains(logs, "token was dropped") {
		t.Fatalf("%v %s", err, logs)
	}
}

func TestClientStamp(t *testing.T) {
	a := tsatest.New(t)
	digest := timestamp.Digest([]byte("test-fixture-payload"))
	c := NewClient(a.URL, "1.2.3.4.5", 2*time.Second)

	tok, err := c.Stamp(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := timestamp.Verify(tok.DER, []byte("test-fixture-payload"), a.Roots); err != nil {
		t.Fatalf("the stored token does not verify: %v", err)
	}
	for name, mode := range map[string]tsatest.Mode{
		"http 503": tsatest.ServerError, "rejected": tsatest.Reject, "wrong nonce": tsatest.WrongNonce,
		"wrong imprint": tsatest.WrongImprint, "garbage": tsatest.Garbage,
	} {
		a.SetMode(mode)
		if _, err := c.Stamp(context.Background(), digest); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewClient(a.URL, "x.y", time.Second).Stamp(context.Background(), digest); err == nil {
		t.Error("a bad policy OID was accepted")
	}
}
