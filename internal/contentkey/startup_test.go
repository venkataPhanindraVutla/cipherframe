package contentkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms/kmstest"
)

type fakeCounter struct {
	usage []db.KEKUsage
	err   error
}

func (f fakeCounter) CountContentKeysByKEK(context.Context) ([]db.KEKUsage, error) {
	return f.usage, f.err
}

func use(provider, version string) db.KEKUsage {
	return db.KEKUsage{KEK: db.KEKRef{Provider: provider, KeyID: "local", Version: version}, Keys: 3}
}

func TestCheckKEKs(t *testing.T) {
	ctx := context.Background()
	reg, err := kms.NewRegistry(localSet(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		usage []db.KEKUsage
		want  string // "" means success
	}{
		{"empty database", nil, ""},
		{"known versions", []db.KEKUsage{use("local", "1"), use("local", "2")}, ""},
		{"missing version", []db.KEKUsage{use("local", "1"), use("local", "7")}, "local version 7"},
		{"unconfigured provider", []db.KEKUsage{use("vault", "3")}, "provider(s) vault"},
		{"both", []db.KEKUsage{use("vault", "3"), use("local", "9")}, "provider(s) vault"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckKEKs(ctx, fakeCounter{usage: tc.usage}, reg)
			switch {
			case tc.want == "" && err != nil:
				t.Fatal(err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("got %v, want mention of %q", err, tc.want)
			}
		})
	}

	if err := CheckKEKs(ctx, fakeCounter{err: errors.New("down")}, reg); err == nil {
		t.Fatal("a failed count must refuse to start")
	}
}

func TestCheckKEKsPresenceOnlyForRemote(t *testing.T) {
	reg, err := kms.NewRegistry(&remoteStub{name: "vault"})
	if err != nil {
		t.Fatal(err)
	}
	u := db.KEKUsage{KEK: db.KEKRef{Provider: "vault", KeyID: "k", Version: "41"}, Keys: 1}
	if err := CheckKEKs(context.Background(), fakeCounter{usage: []db.KEKUsage{u}}, reg); err != nil {
		t.Fatalf("a remote provider's version must not be checked locally: %v", err)
	}
}

type remoteStub struct{ name string }

func (r *remoteStub) Name() string                              { return r.name }
func (*remoteStub) Current(context.Context) (kms.KeyRef, error) { return kms.KeyRef{}, nil }
func (*remoteStub) Wrap(context.Context, []byte, []byte) (kms.Wrapped, error) {
	return kms.Wrapped{}, errors.New("stub")
}

func (*remoteStub) Unwrap(context.Context, kms.Wrapped, []byte) ([]byte, error) {
	return nil, errors.New("stub")
}

// TestRewrapRowLogScan runs a re-wrap, an outage and an integrity failure with a capturing JSON
// log handler and asserts that neither the content key nor a KEK appears in any log or error text.
func TestRewrapRowLogScan(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x6e}, KeyBytes)
	kek := bytes.Repeat([]byte{0x41}, 32)
	oldRow := rowUnder(t, localSet(t, 1), key)

	var logs bytes.Buffer
	var outs []string
	collect := func(err error) {
		if err != nil {
			outs = append(outs, err.Error())
			var e *errs.Error
			if errors.As(err, &e) && e.Unwrap() != nil {
				outs = append(outs, e.Unwrap().Error())
			}
		}
	}

	m := newTestManager(t, &logs, localSet(t, 2))
	_, err := m.rewrapRow(ctx, oldRow)
	collect(err)

	f := kmstest.NewFaulty(localSet(t, 2))
	f.SetOutage(true)
	_, err = newTestManager(t, &logs, f).rewrapRow(ctx, oldRow)
	collect(err)

	f.SetOutage(false)
	f.SetIntegrityFailure(true)
	_, err = newTestManager(t, &logs, f).rewrapRow(ctx, oldRow)
	collect(err)

	outs = append(outs, logs.String())
	if logs.Len() == 0 {
		t.Fatal("the scan saw no logs; the capture is not wired")
	}
	for _, secret := range [][]byte{key, kek} {
		for _, form := range []string{
			string(secret), hex.EncodeToString(secret),
			base64.StdEncoding.EncodeToString(secret), base64.URLEncoding.EncodeToString(secret),
			base64.RawStdEncoding.EncodeToString(secret), base64.RawURLEncoding.EncodeToString(secret),
		} {
			for _, o := range outs {
				if strings.Contains(o, form) {
					t.Fatal("secret material appears in a log or an error")
				}
			}
		}
	}
}
