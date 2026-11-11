package uploads

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

func TestTokenShapeAndHashing(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	text := tok.Reveal()
	if len(text) != TokenLen || !strings.HasPrefix(text, "cfu_") {
		t.Fatalf("token %q has the wrong shape", text)
	}
	h, err := HashToken(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 32 || string(h) != string(tok.Hash()) {
		t.Fatal("HashToken and Token.Hash disagree")
	}
	other, _ := NewToken()
	if other.Reveal() == text || string(other.Hash()) == string(h) {
		t.Fatal("two tokens collided")
	}
	if strings.Contains(string(h), text) {
		t.Fatal("the hash contains the token")
	}
}

func TestHashTokenRejectsMalformedInput(t *testing.T) {
	tok, _ := NewToken()
	good := tok.Reveal()
	for name, bad := range map[string]string{
		"empty":             "",
		"wrong tag":         "cf_" + good[4:],
		"too short":         good[:len(good)-1],
		"too long":          good + "A",
		"not base64url":     "cfu_" + strings.Repeat("!", 43),
		"padding":           good[:len(good)-1] + "=",
		"non canonical":     "cfu_" + strings.Repeat("A", 42) + "B", // trailing bits set
		"api key":           "cf_" + strings.Repeat("a", 12) + "_" + strings.Repeat("b", 43),
		"whitespace":        good + " ",
		"unicode lookalike": "cfu_" + strings.Repeat("é", 21) + "A",
	} {
		if _, err := HashToken(bad); !errors.Is(err, ErrTokenFormat) {
			t.Errorf("%s: err = %v, want ErrTokenFormat", name, err)
		}
	}
}

func TestTokenIsRedactedEverywhere(t *testing.T) {
	tok, _ := NewToken()
	secret := strings.TrimPrefix(tok.Reveal(), "cfu_")
	var sb strings.Builder
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		fmt.Fprintf(&sb, verb+"\n", tok)
		fmt.Fprintf(&sb, verb+"\n", &tok)
	}
	slog.New(slog.NewJSONHandler(&sb, nil)).Info("issued", "token", tok)
	b, err := json.Marshal(map[string]any{"token": tok})
	if err != nil {
		t.Fatal(err)
	}
	sb.Write(b)
	if strings.Contains(sb.String(), secret) {
		t.Fatalf("a printed token leaks its secret:\n%s", sb.String())
	}
}

type fakeGrants struct {
	grant db.UploadGrant
	err   error
	calls int
	last  []byte
}

func (f *fakeGrants) GetUploadGrant(_ context.Context, hash []byte) (db.UploadGrant, error) {
	f.calls++
	f.last = hash
	return f.grant, f.err
}

func TestAuthorizerChecksExpiryAndState(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	tok, _ := NewToken()
	assetID := id.New[id.AssetKind]()
	mk := func(state db.AssetState, tokenExp time.Time, assetExp *time.Time) *fakeGrants {
		return &fakeGrants{grant: db.UploadGrant{
			Asset:          db.Asset{ID: assetID, State: state, UploadExpiresAt: assetExp},
			TokenExpiresAt: tokenExp,
		}}
	}
	future, past := now.Add(time.Hour), now.Add(-time.Second)
	for name, tc := range map[string]struct {
		f  *fakeGrants
		ok bool
	}{
		"valid, created":           {mk(db.AssetCreated, future, &future), true},
		"valid, uploading":         {mk(db.AssetUploading, future, nil), true},
		"expired token":            {mk(db.AssetUploading, past, &future), false},
		"token expiring right now": {mk(db.AssetUploading, now, &future), false},
		"expired asset window":     {mk(db.AssetUploading, future, &past), false},
		"committed":                {mk(db.AssetCommitted, future, &future), false},
		"processing":               {mk(db.AssetProcessing, future, &future), false},
		"failed (aborted)":         {mk(db.AssetFailed, future, &future), false},
		"deleted":                  {mk(db.AssetDeleted, future, &future), false},
		"unknown token":            {&fakeGrants{err: errs.New(errs.NotFound, "resource not found")}, false},
	} {
		t.Run(name, func(t *testing.T) {
			a := NewAuthorizer(tc.f, func() time.Time { return now })
			g, err := a.Authorize(context.Background(), tok.Reveal())
			if tc.ok {
				if err != nil || g.Asset.ID != assetID {
					t.Fatalf("grant %+v, err %v", g, err)
				}
				return
			}
			var e *errs.Error
			if !errors.As(err, &e) || e.Code != errs.Unauthenticated {
				t.Fatalf("err = %v, want unauthenticated", err)
			}
			if !strings.Contains(e.Detail, "missing, invalid or expired") {
				t.Fatalf("detail %q does not use the generic wording", e.Detail)
			}
		})
	}

	t.Run("looks the token up by its hash, never by the token", func(t *testing.T) {
		f := mk(db.AssetUploading, future, nil)
		if _, err := NewAuthorizer(f, func() time.Time { return now }).Authorize(context.Background(), tok.Reveal()); err != nil {
			t.Fatal(err)
		}
		if string(f.last) != string(tok.Hash()) || strings.Contains(string(f.last), tok.Reveal()) {
			t.Fatal("the store was not asked for the hash")
		}
	})
	t.Run("a malformed token never reaches the store", func(t *testing.T) {
		f := mk(db.AssetUploading, future, nil)
		if _, err := NewAuthorizer(f, nil).Authorize(context.Background(), "cfu_short"); err == nil || f.calls != 0 {
			t.Fatalf("err %v, store calls %d", err, f.calls)
		}
	})
	t.Run("a database failure is not a token verdict", func(t *testing.T) {
		f := &fakeGrants{err: errs.New(errs.DependencyUnavailable, "database unavailable")}
		_, err := NewAuthorizer(f, nil).Authorize(context.Background(), tok.Reveal())
		var e *errs.Error
		if !errors.As(err, &e) || e.Code != errs.DependencyUnavailable {
			t.Fatalf("err = %v, want dependency_unavailable", err)
		}
	})
}

func testLimits() Limits {
	return Limits{MaxSourceBytes: 10 << 30, PartBytes: 64 << 20, TokenTTL: 24 * time.Hour}
}

func code(err error) errs.Code {
	var e *errs.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestCheckSize(t *testing.T) {
	l := testLimits()
	for size, want := range map[int64]errs.Code{
		-1: errs.InvalidRequest, 0: errs.InvalidRequest, 1: "", 10 << 30: "", 10<<30 + 1: errs.PayloadTooLarge,
	} {
		if got := code(l.CheckSize(size)); got != want {
			t.Errorf("CheckSize(%d) = %q, want %q", size, got, want)
		}
	}
}

func TestLimitsValidate(t *testing.T) {
	good := testLimits()
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]Limits{
		"no max":             {PartBytes: good.PartBytes, TokenTTL: good.TokenTTL},
		"part below 5 MiB":   {MaxSourceBytes: 1 << 30, PartBytes: 4 << 20, TokenTTL: good.TokenTTL},
		"part above 5 GiB":   {MaxSourceBytes: 1 << 30, PartBytes: 6 << 30, TokenTTL: good.TokenTTL},
		"no ttl":             {MaxSourceBytes: 1 << 30, PartBytes: good.PartBytes},
		"too many parts":     {MaxSourceBytes: 1 << 40, PartBytes: 5 << 20, TokenTTL: good.TokenTTL},
		"limits from config": {},
	} {
		if name == "limits from config" {
			l = LimitsFrom(config.Uploads{MaxSourceBytes: config.DefaultMaxSourceBytes, TokenTTL: config.DefaultUploadTokenTTL, PartBytes: config.DefaultUploadPartBytes})
			if err := l.Validate(); err != nil {
				t.Errorf("the default configuration is not valid: %v", err)
			}
			continue
		}
		if err := l.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckContentType(t *testing.T) {
	for _, ok := range []string{"", "video/mp4", "video/x-matroska", "application/octet-stream", "video/mp2t"} {
		if err := CheckContentType(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"video", "video/", "/mp4", "Video/MP4", "video/mp4; codecs=avc1", "video/mp4 ", "video\n/mp4", "a/b/c", strings.Repeat("a", 300) + "/b"} {
		if code(CheckContentType(bad)) != errs.InvalidRequest {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheckPartNumber(t *testing.T) {
	for n, ok := range map[int]bool{-1: false, 0: false, 1: true, 10000: true, 10001: false} {
		if (CheckPartNumber(n) == nil) != ok {
			t.Errorf("part %d: ok = %v", n, !ok)
		}
	}
}

func TestCheckPart(t *testing.T) {
	l := testLimits()
	const declared = 200 << 20
	for name, tc := range map[string]struct {
		size, other int64
		want        errs.Code
	}{
		"a full part":              {64 << 20, 0, ""},
		"a small last part":        {1, 128 << 20, ""},
		"exactly fills the asset":  {64 << 20, declared - 64<<20, ""},
		"empty":                    {0, 0, errs.InvalidRequest},
		"larger than the part":     {64<<20 + 1, 0, errs.PayloadTooLarge},
		"overruns the declaration": {64 << 20, declared - 1, errs.InvalidRequest},
	} {
		if got := code(l.CheckPart(tc.size, declared, tc.other)); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

func parts(sizes ...int64) []db.UploadPart {
	out := make([]db.UploadPart, len(sizes))
	for i, s := range sizes {
		out[i] = db.UploadPart{PartNumber: i + 1, ETag: `"e"`, SizeBytes: s}
	}
	return out
}

func TestValidateParts(t *testing.T) {
	const mib = 1 << 20
	const part = 8 * mib
	for name, tc := range map[string]struct {
		parts    []db.UploadPart
		declared int64
		ok       bool
	}{
		"one small part":        {parts(3), 3, true},
		"full parts and a tail": {parts(part, part, 1), 2*part + 1, true},
		"all full":              {parts(part, part), 2 * part, true},
		"none":                  {nil, 1, false},
		"gap":                   {[]db.UploadPart{{PartNumber: 1, SizeBytes: part}, {PartNumber: 3, SizeBytes: part}}, 2 * part, false},
		"starts at 2":           {[]db.UploadPart{{PartNumber: 2, SizeBytes: part}}, part, false},
		"short middle part":     {parts(part, 5*mib-1, part), 2*part + 5*mib - 1, false},
		"minimum middle part":   {parts(part, 5*mib, part), 2*part + 5*mib, true},
		"oversized part":        {parts(part + 1), part + 1, false},
		"total short":           {parts(part, part), 2*part + 1, false},
		"total long":            {parts(part, part), 2*part - 1, false},
	} {
		err := ValidateParts(tc.parts, tc.declared, part)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok = %v", name, err, tc.ok)
		}
		if err != nil && code(err) != errs.Conflict {
			t.Errorf("%s: code %q, want conflict", name, code(err))
		}
	}
}

func TestProcessArgsCarryOnlyIDs(t *testing.T) {
	a := ProcessArgs{TenantID: id.New[id.TenantKind](), AssetID: id.New[id.AssetKind]()}
	if a.Kind() != "asset.process" {
		t.Fatalf("kind = %q", a.Kind())
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || !strings.HasPrefix(m["tenant_id"], "ten_") || !strings.HasPrefix(m["asset_id"], "ast_") {
		t.Fatalf("job arguments %s are not just a tenant ID and an asset ID", b)
	}
}

func TestAdvisoryKeyIsStableAndSpread(t *testing.T) {
	first, second := advisoryKey("a"), advisoryKey("a")
	if first != second {
		t.Fatal("the key is not deterministic")
	}
	seen := map[int64]bool{}
	for i := range 1000 {
		seen[advisoryKey(fmt.Sprintf("ast_%d", i))] = true
	}
	if len(seen) != 1000 {
		t.Fatalf("%d distinct keys for 1000 uploads", len(seen))
	}
}
