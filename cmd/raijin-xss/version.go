package main

import (
	"runtime/debug"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-xss/internal/dalfox"
)

// version is the release this binary was installed as, or "dev" for a local build.
var version = buildVersion()

// buildVersion returns the module version from the build info when the binary was installed with
// go install ...@vX.Y.Z (or @latest), else "dev" with the VCS revision of a local go build.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	return versionFrom(info)
}

func versionFrom(info *debug.BuildInfo) string {
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch {
		case s.Key == "vcs.revision":
			rev = s.Value
			if len(rev) > 12 {
				rev = rev[:12]
			}
		case s.Key == "vcs.modified" && s.Value == "true":
			dirty = "+dirty"
		}
	}
	if rev == "" {
		return "dev"
	}
	return "dev-" + rev + dirty
}

// versionLine is what --version prints: the release and the engine versions it was tested with.
func versionLine() string {
	line := "raijin-xss " + version
	engines, err := dalfox.Engines()
	if err != nil || len(engines) == 0 {
		return line
	}
	names := make([]string, 0, len(engines))
	for name := range engines {
		names = append(names, name)
	}
	sort.Strings(names)
	tested := make([]string, len(names))
	for i, name := range names {
		tested[i] = name + " " + engines[name].Version
	}
	return line + " (tested with " + strings.Join(tested, ", ") + ")"
}
