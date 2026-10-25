package dalfox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEnginesHasDalfox(t *testing.T) {
	m, err := Engines()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := m["dalfox"]
	if !ok || ParseVersion(e.Version) == nil || e.Go == "" {
		t.Errorf("engines.json needs a dalfox entry with a version and an install source: %+v", m)
	}
}

func TestParseVersion(t *testing.T) {
	// "dalfox version" output: the banner on stderr, then the colored version.
	sample := "\n    _..._\n  .' .::::.   __   _   _    ___ _ __ __\n :  :::::::: |  \\ / \\ | |  | __/ \\\\ V /\n" +
		"\U0001F319\U0001F98A Dalfox is a powerful open-source XSS scanner and utility focused on automation.\n\x1b[93mv2.9.2\x1b[0m\n"
	for in, want := range map[string][]int{sample: {2, 9, 2}, "v3.0.0-beta\n": {3, 0, 0}, "2.10.1": {2, 10, 1}, "unknown": nil} {
		if got := ParseVersion(in); !reflect.DeepEqual(got, want) {
			t.Errorf("ParseVersion(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestUntested(t *testing.T) {
	tested := []int{2, 9, 2}
	for _, c := range []struct {
		v    []int
		want bool
	}{{[]int{2, 9, 2}, false}, {[]int{2, 9, 3}, false}, {[]int{2, 12, 0}, false}, {[]int{2, 9, 1}, true},
		{[]int{2, 8, 9}, true}, {[]int{3, 0, 0}, true}, {[]int{1, 9, 9}, true}, {nil, false}} {
		if got := Untested(c.v, tested); got != c.want {
			t.Errorf("Untested(%v) = %v, want %v", c.v, got, c.want)
		}
	}
}

// The fake dalfox answers "version" with a version derived from engines.json, so a bump does not break this.
func TestCheckVersionHint(t *testing.T) {
	m, _ := Engines()
	tested := ParseVersion(m["dalfox"].Version)
	fake := func(v string) string {
		p := filepath.Join(t.TempDir(), "dalfox")
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho v"+v+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if hint := CheckVersion(context.Background(), fake(m["dalfox"].Version)); hint != "" {
		t.Errorf("tested version warned: %q", hint)
	}
	other := fmt.Sprintf("%d.0.0", tested[0]+1)
	hint := CheckVersion(context.Background(), fake(other))
	if !strings.Contains(hint, "dalfox "+other) || !strings.HasSuffix(hint, ", or run raijin-mcp update") {
		t.Errorf("hint = %q", hint)
	}
}
