package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
)

// Without the edge's public URL the browser-session route is left out, with a warning that names
// the setting: the edge role still starts, as it did before the route existed.
func TestEdgeViewerAuthIsOffWithoutThePublicURL(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	viewer, err := newEdgeViewerAuth(nil, nil, nil, nil, nil, nil, &config.Config{}, log)
	if err != nil || viewer != nil {
		t.Fatalf("viewer %v, err %v", viewer, err)
	}
	if !strings.Contains(logs.String(), config.EnvEdgePublicURL) {
		t.Fatalf("no warning naming %s: %q", config.EnvEdgePublicURL, logs.String())
	}
}
