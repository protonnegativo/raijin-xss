package main

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-xss/internal/dalfox"
)

func TestVersionFrom(t *testing.T) {
	rev := func(modified string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123"}, {Key: "vcs.modified", Value: modified}}}
	}
	for want, info := range map[string]*debug.BuildInfo{
		"v0.1.3":                 {Main: debug.Module{Version: "v0.1.3"}},
		"dev":                    {Main: debug.Module{Version: "(devel)"}},
		"dev-0123456789ab":       rev("false"),
		"dev-0123456789ab+dirty": rev("true"),
	} {
		if got := versionFrom(info); got != want {
			t.Errorf("versionFrom = %q, want %q", got, want)
		}
	}
}

func TestBuildVersionPrefersReleaseVersion(t *testing.T) {
	old := releaseVersion
	defer func() { releaseVersion = old }()
	releaseVersion = "v9.9.9"
	if got := buildVersion(); got != "v9.9.9" {
		t.Errorf("buildVersion = %q, want v9.9.9", got)
	}
}

func TestVersionLine(t *testing.T) {
	engines, _ := dalfox.Engines()
	var out bytes.Buffer
	if code := run([]string{"--version"}, strings.NewReader(""), &out, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	want := "raijin-xss " + version + " (tested with dalfox " + engines["dalfox"].Version + ")\n"
	if out.String() != want {
		t.Errorf("--version = %q, want %q", out.String(), want)
	}
}
