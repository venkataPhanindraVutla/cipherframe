package token

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
)

func loadKeys(t *testing.T, entries, current string) config.PlaybackKeys {
	t.Helper()
	e := map[string]string{
		config.EnvDatabaseURL:             "postgres://db:5432/cipherframe",
		config.EnvS3SourceBucket:          "cf-source",
		config.EnvS3DeliveryBucket:        "cf-delivery",
		config.EnvAPIKeyPeppers:           "1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 32)),
		config.EnvAPIKeyPepperCurrent:     "1",
		config.EnvKMSLocalKEKs:            "1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("k"), 32)),
		config.EnvKMSLocalKEKCurrent:      "1",
		config.EnvPlaybackTokenKeys:       entries,
		config.EnvPlaybackTokenKeyCurrent: current,
	}
	c, err := config.Load(func(k string) (string, bool) { v, ok := e[k]; return v, ok }, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.Playback
}

func TestKeyringFromConfig(t *testing.T) {
	enc := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	keys := loadKeys(t, "1:"+enc('a')+",2:"+enc('b'), "2")
	k, err := KeyringFromConfig(keys)
	if err != nil {
		t.Fatal(err)
	}
	c := claims(t, ScopeSegment)
	tok, err := k.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Split(tok, ".")[2] != "2" {
		t.Fatal("did not sign with the current key")
	}
	if _, err := k.Verify(tok, t0, ScopeSegment, c.AssetID); err != nil {
		t.Fatal(err)
	}
	// A keyring that only knows key 1 can verify tokens made with key 1.
	only1, err := KeyringFromConfig(loadKeys(t, "1:"+enc('a'), "1"))
	if err != nil {
		t.Fatal(err)
	}
	old, _ := only1.Sign(c)
	if _, err := k.Verify(old, t0, ScopeSegment, c.AssetID); err != nil {
		t.Fatalf("old key after rotation: %v", err)
	}
}

func TestKeyringFromConfigUnset(t *testing.T) {
	if _, err := KeyringFromConfig(config.PlaybackKeys{}); err == nil {
		t.Fatal("empty config accepted")
	}
}
