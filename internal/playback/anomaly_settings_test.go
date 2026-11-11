package playback

import (
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
)

func TestValidateAnomalySettings(t *testing.T) {
	type edit func(*db.PlaybackSettings)
	ok := map[string]edit{
		"both disabled": func(s *db.PlaybackSettings) { s.AnomalySessionsPerViewer10m, s.AnomalySegmentsWithoutKey = 0, 0 },
		"maximums": func(s *db.PlaybackSettings) {
			s.AnomalySessionsPerViewer10m, s.AnomalySegmentsWithoutKey = 1000, 100000
		},
		"every kind": func(s *db.PlaybackSettings) { s.AutoRevoke = append([]string(nil), db.AutoRevokeKinds...) },
		"nil list":   func(s *db.PlaybackSettings) { s.AutoRevoke = nil },
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
		"sessions negative": {func(s *db.PlaybackSettings) { s.AnomalySessionsPerViewer10m = -1 }, "anomaly_sessions_per_viewer_10m"},
		"sessions high":     {func(s *db.PlaybackSettings) { s.AnomalySessionsPerViewer10m = 1001 }, "anomaly_sessions_per_viewer_10m"},
		"segments negative": {func(s *db.PlaybackSettings) { s.AnomalySegmentsWithoutKey = -1 }, "anomaly_segments_without_key"},
		"segments high":     {func(s *db.PlaybackSettings) { s.AnomalySegmentsWithoutKey = 100001 }, "anomaly_segments_without_key"},
		"session_limit":     {func(s *db.PlaybackSettings) { s.AutoRevoke = []string{"session_limit"} }, "auto_revoke[0]"},
		"unknown kind":      {func(s *db.PlaybackSettings) { s.AutoRevoke = []string{"key_rate", "nope"} }, "auto_revoke[1]"},
		"repeated kind":     {func(s *db.PlaybackSettings) { s.AutoRevoke = []string{"key_rate", "key_rate"} }, "auto_revoke[1]"},
		"value not echoed":  {func(s *db.PlaybackSettings) { s.AutoRevoke = []string{"test-fixture-secret"} }, "auto_revoke[0]"},
	}
	for name, c := range bad {
		s := db.DefaultPlaybackSettings()
		c.edit(&s)
		f := ValidateSettings(s)
		if !fields(f)[c.field] {
			t.Errorf("%s: field errors = %v, want one for %s", name, f, c.field)
		}
		for _, e := range f {
			if strings.Contains(e.Message, "test-fixture-secret") {
				t.Errorf("%s: the message quotes the submitted value: %q", name, e.Message)
			}
		}
	}
}
