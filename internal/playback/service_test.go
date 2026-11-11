package playback

import (
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

func TestValidateViewerID(t *testing.T) {
	for name, v := range map[string]string{
		"one char":      "a",
		"max chars":     strings.Repeat("v", 128),
		"max multibyte": strings.Repeat("é", 128),
		"with space":    "user 42",
		"punctuation":   "u/42:x@y.z",
		"cjk":           "テスト",
		"emoji":         "viewer-😀",
	} {
		if err := ValidateViewerID(v); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, v := range map[string]string{
		"empty":        "",
		"too long":     strings.Repeat("v", 129),
		"nul":          "a\x00b",
		"newline":      "a\nb",
		"carriage":     "a\rb",
		"tab":          "a\tb",
		"escape":       "a\x1bb",
		"delete":       "a\x7fb",
		"c1 control":   "a\u0085b",
		"line sep":     "a\u2028b",
		"bidi":         "a\u202eb",
		"zero width":   "a\u200bb",
		"invalid utf8": "a\xffb",
		"nbsp":         "a\u00a0b",
	} {
		if err := ValidateViewerID(v); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateSettingsDefaultsAreValid(t *testing.T) {
	if f := ValidateSettings(db.DefaultPlaybackSettings()); len(f) != 0 {
		t.Fatalf("defaults are invalid: %v", f)
	}
}

func fields(f []errs.FieldError) map[string]bool {
	m := map[string]bool{}
	for _, e := range f {
		m[e.Field] = true
	}
	return m
}

func TestValidateSettingsRanges(t *testing.T) {
	type edit func(*db.PlaybackSettings)
	ok := map[string]edit{
		"minimums": func(s *db.PlaybackSettings) {
			s.TokenTTLSeconds, s.HeartbeatIntervalSeconds, s.IdleTimeoutSeconds = 60, 10, 30
			s.SessionMaxSeconds, s.MaxSessionsPerViewer, s.KeyFetchesPerToken, s.KeyRequestsPerMinute = 300, 0, 1, 1
		},
		"maximums": func(s *db.PlaybackSettings) {
			s.TokenTTLSeconds, s.HeartbeatIntervalSeconds, s.IdleTimeoutSeconds = 3600, 600, 3600
			s.SessionMaxSeconds, s.MaxSessionsPerViewer, s.KeyFetchesPerToken, s.KeyRequestsPerMinute = 86400, 100, 1000, 600
		},
		"heartbeat just below ttl": func(s *db.PlaybackSettings) { s.HeartbeatIntervalSeconds, s.TokenTTLSeconds = 59, 60 },
	}
	for name, e := range ok {
		s := db.DefaultPlaybackSettings()
		e(&s)
		if f := ValidateSettings(s); len(f) != 0 {
			t.Errorf("%s: %v", name, f)
		}
	}
	bad := map[string]struct {
		edit  edit
		field string
	}{
		"ttl low":           {func(s *db.PlaybackSettings) { s.TokenTTLSeconds = 59 }, "token_ttl_seconds"},
		"ttl high":          {func(s *db.PlaybackSettings) { s.TokenTTLSeconds = 3601 }, "token_ttl_seconds"},
		"heartbeat low":     {func(s *db.PlaybackSettings) { s.HeartbeatIntervalSeconds = 9 }, "heartbeat_interval_seconds"},
		"heartbeat high":    {func(s *db.PlaybackSettings) { s.HeartbeatIntervalSeconds = 601 }, "heartbeat_interval_seconds"},
		"heartbeat == ttl":  {func(s *db.PlaybackSettings) { s.HeartbeatIntervalSeconds, s.TokenTTLSeconds = 100, 100 }, "heartbeat_interval_seconds"},
		"heartbeat > ttl":   {func(s *db.PlaybackSettings) { s.HeartbeatIntervalSeconds, s.TokenTTLSeconds = 200, 100 }, "heartbeat_interval_seconds"},
		"heartbeat == idle": {func(s *db.PlaybackSettings) { s.HeartbeatIntervalSeconds, s.IdleTimeoutSeconds = 100, 100 }, "heartbeat_interval_seconds"},
		"idle low":          {func(s *db.PlaybackSettings) { s.IdleTimeoutSeconds = 29 }, "idle_timeout_seconds"},
		"idle high":         {func(s *db.PlaybackSettings) { s.IdleTimeoutSeconds = 3601 }, "idle_timeout_seconds"},
		"session max low":   {func(s *db.PlaybackSettings) { s.SessionMaxSeconds = 299 }, "session_max_seconds"},
		"session max high":  {func(s *db.PlaybackSettings) { s.SessionMaxSeconds = 86401 }, "session_max_seconds"},
		"max sessions neg":  {func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = -1 }, "max_sessions_per_viewer"},
		"max sessions high": {func(s *db.PlaybackSettings) { s.MaxSessionsPerViewer = 101 }, "max_sessions_per_viewer"},
		"fetches zero":      {func(s *db.PlaybackSettings) { s.KeyFetchesPerToken = 0 }, "key_fetches_per_token"},
		"fetches high":      {func(s *db.PlaybackSettings) { s.KeyFetchesPerToken = 1001 }, "key_fetches_per_token"},
		"rpm zero":          {func(s *db.PlaybackSettings) { s.KeyRequestsPerMinute = 0 }, "key_requests_per_minute"},
		"rpm high":          {func(s *db.PlaybackSettings) { s.KeyRequestsPerMinute = 601 }, "key_requests_per_minute"},
		"21 origins": {func(s *db.PlaybackSettings) {
			for i := range 21 {
				s.AllowedOrigins = append(s.AllowedOrigins, "https://h"+strings.Repeat("a", i+1)+".example.com")
			}
		}, "allowed_origins"},
	}
	for name, c := range bad {
		s := db.DefaultPlaybackSettings()
		c.edit(&s)
		f := ValidateSettings(s)
		if !fields(f)[c.field] {
			t.Errorf("%s: field errors = %v, want one for %s", name, f, c.field)
		}
	}
	// Every problem is reported at once, in field order.
	s := db.DefaultPlaybackSettings()
	s.TokenTTLSeconds, s.KeyFetchesPerToken, s.AllowedOrigins = 1, 0, []string{"*"}
	if f := ValidateSettings(s); len(f) < 3 || f[0].Field != "token_ttl_seconds" {
		t.Errorf("multiple errors = %v", f)
	}
}

func TestValidateSettingsOrigins(t *testing.T) {
	for _, o := range []string{
		"https://example.com",
		"https://app.example.com",
		"https://example.com:8443",
		"https://a-b.example.co.uk",
		"https://192.0.2.7",
		"http://localhost",
		"http://localhost:3000",
		"https://localhost",
	} {
		s := db.DefaultPlaybackSettings()
		s.AllowedOrigins = []string{o}
		if f := ValidateSettings(s); len(f) != 0 {
			t.Errorf("%s rejected: %v", o, f)
		}
	}
	for _, o := range []string{
		"",
		"example.com",
		"//example.com",
		"https://",
		"https://*.example.com",
		"*",
		"https://example.*",
		"http://example.com",
		"http://127.0.0.1:3000",
		"ftp://example.com",
		"https://example.com/",
		"https://example.com/path",
		"https://example.com?x=1",
		"https://example.com#frag",
		"https://user@example.com",
		"https://user:pw@example.com",
		"https://Example.com",
		"https://example.com:",
		"https://example.com:0",
		"https://example.com:65536",
		"https://example.com:08443",
		"https://example.com:443",
		"http://localhost:80",
		"https://example..com",
		"https://-example.com",
		"https://exa_mple.com",
		"https://[::1]",
		"https://example.com ",
		" https://example.com",
		"https://exämple.com",
		"mailto:a@example.com",
		"null",
		"https://" + strings.Repeat("a", 64) + ".example.com",
	} {
		s := db.DefaultPlaybackSettings()
		s.AllowedOrigins = []string{o}
		f := ValidateSettings(s)
		if len(f) != 1 || f[0].Field != "allowed_origins[0]" {
			t.Errorf("%q: field errors = %v, want one for allowed_origins[0]", o, f)
			continue
		}
		// Messages are fixed text: nothing submitted comes back, credentials least of all.
		if strings.Contains(f[0].Message, "user") || strings.Contains(f[0].Message, "pw") {
			t.Errorf("%q: the message quotes the value: %s", o, f[0].Message)
		}
	}
	// Indexes point at the offending entries, and a repeat is an error on the second copy.
	s := db.DefaultPlaybackSettings()
	s.AllowedOrigins = []string{"https://a.example.com", "https://*.example.com", "https://a.example.com"}
	f := ValidateSettings(s)
	if len(f) != 2 || f[0].Field != "allowed_origins[1]" || f[1].Field != "allowed_origins[2]" {
		t.Fatalf("field errors = %v", f)
	}
	// Exactly 20 is allowed.
	s.AllowedOrigins = nil
	for i := range 20 {
		s.AllowedOrigins = append(s.AllowedOrigins, "https://h"+strings.Repeat("a", i+1)+".example.com")
	}
	if f := ValidateSettings(s); len(f) != 0 {
		t.Fatalf("20 origins rejected: %v", f)
	}
}
