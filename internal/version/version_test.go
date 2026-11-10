package version

import (
	"runtime/debug"
	"testing"
)

func TestFromBuildInfo(t *testing.T) {
	tests := []struct {
		name string
		v    string
		bi   *debug.BuildInfo
		want Info
	}{
		{
			name: "no build info",
			v:    "dev",
			bi:   nil,
			want: Info{Version: "dev"},
		},
		{
			name: "vcs settings",
			v:    "v1.0.0",
			bi: &debug.BuildInfo{
				GoVersion: "go1.27.3",
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "abc123"},
					{Key: "vcs.modified", Value: "true"},
					{Key: "GOOS", Value: "linux"},
				},
			},
			want: Info{Version: "v1.0.0", Commit: "abc123", Modified: true, GoVersion: "go1.27.3"},
		},
		{
			name: "clean tree",
			v:    "v1.0.0",
			bi: &debug.BuildInfo{
				GoVersion: "go1.27.3",
				Settings:  []debug.BuildSetting{{Key: "vcs.modified", Value: "false"}},
			},
			want: Info{Version: "v1.0.0", GoVersion: "go1.27.3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fromBuildInfo(tt.v, tt.bi); got != tt.want {
				t.Errorf("fromBuildInfo() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestGetUsesVersionVariable(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "v9.9.9"
	if got := Get().Version; got != "v9.9.9" {
		t.Errorf("Get().Version = %q, want %q", got, "v9.9.9")
	}
}
