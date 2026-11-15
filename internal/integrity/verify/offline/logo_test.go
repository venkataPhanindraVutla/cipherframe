package offline_test

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/jcs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline/offlinetest"
)

// A manifest that records a logo still opens and verifies offline, the logo is part of what the
// signature covers, and the media paths verify as they did.
func TestManifestWithALogoVerifiesOffline(t *testing.T) {
	f := offlinetest.New(t)
	m := f.Built.Manifest
	logo := &manifest.Logo{SHA256: strings.Repeat("cd", 32), Version: "lgo_1", Corner: "bottom_right", OpacityPercent: 70, WidthPercent: 15}
	m.Encoder.Logo = logo
	masked := *m.Masked
	masked.Logo = logo
	m.Masked = &masked
	canonical, err := jcs.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	k := offlinetest.NewKey("sk_a", "a")
	env := offlinetest.Sign(t, canonical, k)
	keys, err := offline.ParseKeySet(offlinetest.KeySetJSON([]offlinetest.Key{k}, map[string]string{"sk_a": "active"}))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := offline.Open(env, keys)
	if err != nil {
		t.Fatal(err)
	}
	if got := signed.Manifest.Encoder.Logo; got == nil || *got != *logo {
		t.Errorf("logo = %+v", got)
	}
	if got := signed.Manifest.Masked.Logo; got == nil || *got != *logo {
		t.Errorf("masked logo = %+v", got)
	}
	sum := sha256.Sum256([]byte("master"))
	if r := offline.VerifyArtifact(env, keys, "master.m3u8", sum, "original"); r.Outcome != offline.Ours {
		t.Errorf("master playlist: %+v", r)
	}
	if !strings.Contains(string(canonical), `"opacity_percent":70`) {
		t.Error("the signed bytes do not carry the logo's placement")
	}
}
