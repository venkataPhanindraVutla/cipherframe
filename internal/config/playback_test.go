package config

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func playbackEnv() env {
	return base.with(
		EnvPlaybackTokenKeys, "1:"+pepper('p', 32),
		EnvPlaybackTokenKeyCurrent, "1",
	)
}

func TestPlaybackKeysOptionalAtLoad(t *testing.T) {
	c, err := load(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Playback.Configured() || c.Playback.Len() != 0 {
		t.Fatal("keys appeared from nowhere")
	}
	err = c.Playback.Require()
	if err == nil || !strings.Contains(err.Error(), EnvPlaybackTokenKeys) || !strings.Contains(err.Error(), EnvPlaybackTokenKeyCurrent) {
		t.Fatalf("Require = %v, want an error naming both variables", err)
	}
}

func TestPlaybackKeysLoad(t *testing.T) {
	c, err := load(playbackEnv().with(
		EnvPlaybackTokenKeys, "2:"+pepper('b', 32)+" , 1:"+pepper('a', 48),
		EnvPlaybackTokenKeyCurrent, "2",
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Playback.Require(); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(c.Playback.Versions()); got != "[1 2]" {
		t.Fatalf("versions %s", got)
	}
	old, ok := c.Playback.Get(1)
	if !ok || len(old.Reveal()) != 48 {
		t.Fatal("key 1 lost")
	}
	if _, ok := c.Playback.Get(3); ok {
		t.Fatal("unexpected key 3")
	}
	if cur, s := c.Playback.Current(); cur != 2 || s.Reveal() != strings.Repeat("b", 32) {
		t.Fatal("current wrong")
	}
	if m := c.Playback.KeyMaterial(); len(m) != 2 || string(m[2]) != strings.Repeat("b", 32) {
		t.Fatal("KeyMaterial wrong")
	}
}

func TestPlaybackKeysInvalid(t *testing.T) {
	good := playbackEnv()
	tests := []struct {
		name string
		env  env
		want string
	}{
		{"keys without current", good.with(EnvPlaybackTokenKeyCurrent, "\x00"), EnvPlaybackTokenKeyCurrent},
		{"current without keys", good.with(EnvPlaybackTokenKeys, "\x00"), EnvPlaybackTokenKeys},
		{"no colon", good.with(EnvPlaybackTokenKeys, pepper('a', 32)), "kid:base64"},
		{"bad kid", good.with(EnvPlaybackTokenKeys, "x:"+pepper('a', 32)), "invalid key ID"},
		{"zero kid", good.with(EnvPlaybackTokenKeys, "0:"+pepper('a', 32)), "invalid key ID"},
		{"negative kid", good.with(EnvPlaybackTokenKeys, "-1:"+pepper('a', 32)), "invalid key ID"},
		{"bad base64", good.with(EnvPlaybackTokenKeys, "1:!!!"), "base64"},
		{"short key", good.with(EnvPlaybackTokenKeys, "1:"+pepper('a', 31)), "shorter than 32"},
		{"duplicate", good.with(EnvPlaybackTokenKeys, "1:"+pepper('a', 32)+",1:"+pepper('b', 32)), "more than once"},
		{"empty entry", good.with(EnvPlaybackTokenKeys, "1:"+pepper('a', 32)+","), EnvPlaybackTokenKeys},
		{"current not a number", good.with(EnvPlaybackTokenKeyCurrent, "one"), "positive integer"},
		{"current not in set", good.with(EnvPlaybackTokenKeyCurrent, "2"), "not in"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(tc.env, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), pepper('a', 32)) || strings.Contains(err.Error(), pepper('p', 32)) {
				t.Fatal("error leaks a key")
			}
		})
	}
}

func TestPlaybackKeysFromFile(t *testing.T) {
	e := playbackEnv().with(EnvPlaybackTokenKeys, "\x00", EnvPlaybackTokenKeys+"_FILE", "/run/secrets/playback")
	c, err := load(e, map[string]string{"/run/secrets/playback": "1:" + pepper('z', 40) + "\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, s := c.Playback.Current(); len(s.Reveal()) != 40 {
		t.Fatal("key from file not parsed")
	}
	both := playbackEnv().with(EnvPlaybackTokenKeys+"_FILE", "/x")
	if _, err := load(both, nil); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Fatalf("direct and _FILE together: %v", err)
	}
}

func TestPlaybackKeysPlaceholders(t *testing.T) {
	ph := base64.StdEncoding.EncodeToString([]byte(PlaceholderPrefix + strings.Repeat("x", 24)))
	dev := playbackEnv().with(EnvPlaybackTokenKeys, "1:"+ph)
	if _, err := load(dev, nil); err != nil {
		t.Fatalf("placeholder rejected in development: %v", err)
	}
	if _, err := load(prod.with(EnvPlaybackTokenKeys, "1:"+ph, EnvPlaybackTokenKeyCurrent, "1"), nil); err == nil ||
		!strings.Contains(err.Error(), "development placeholder") {
		t.Fatalf("placeholder accepted in production: %v", err)
	}
	if _, err := load(prod.with(EnvPlaybackTokenKeys, "1:"+pepper('a', 32), EnvPlaybackTokenKeyCurrent, "1"), nil); err != nil {
		t.Fatalf("real key rejected in production: %v", err)
	}
}

func TestPlaybackKeysNeverPrinted(t *testing.T) {
	c, err := load(playbackEnv(), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Repeat("p", 32)
	var sb strings.Builder
	for _, v := range []any{c.Playback, &c.Playback} {
		fmt.Fprintf(&sb, "%v %+v %#v %s %x %d\n", v, v, v, v, v, v)
	}
	fmt.Fprint(&sb, c.LogValue())
	fmt.Fprintf(&sb, "%+v", c)
	if strings.Contains(sb.String(), raw) || strings.Contains(sb.String(), pepper('p', 32)) {
		t.Fatalf("playback key printed: %s", sb.String())
	}
	if !strings.Contains(fmt.Sprint(c.LogValue()), "playback_token_keys") {
		t.Fatal("LogValue lacks the playback key group")
	}
	var _ slog.LogValuer = c
}
