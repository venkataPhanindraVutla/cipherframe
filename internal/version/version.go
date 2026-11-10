// Package version reports the build identity of Cipherframe binaries.
//
// Release builds set Version with -ldflags "-X .../internal/version.Version=v1.2.3".
// Development builds fall back to the VCS information the Go toolchain embeds.
package version

import (
	"runtime/debug"
)

// Version is the release version. It is overridden at link time for release builds.
var Version = "dev"

// Info describes a build.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	Modified  bool   `json:"modified,omitempty"`
	GoVersion string `json:"goVersion"`
}

// Get returns the build information of the running binary.
func Get() Info {
	return fromBuildInfo(Version, readBuildInfo())
}

var readBuildInfo = func() *debug.BuildInfo {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return bi
}

func fromBuildInfo(v string, bi *debug.BuildInfo) Info {
	info := Info{Version: v}
	if bi == nil {
		return info
	}
	info.GoVersion = bi.GoVersion
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			info.Commit = s.Value
		case "vcs.modified":
			info.Modified = s.Value == "true"
		}
	}
	return info
}
