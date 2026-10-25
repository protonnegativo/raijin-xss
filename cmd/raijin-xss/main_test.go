package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func replay(t *testing.T, extra ...string) (string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	args := append([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, extra...)
	if code := run(args, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	return out.String(), errb.String()
}

func TestNoBannerByDefault(t *testing.T) {
	out, errs := replay(t)
	if errs != "" {
		t.Errorf("stderr should be empty without --banner, got %q", errs)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	out, errs := replay(t, "--banner")
	if !strings.Contains(errs, "TGT-LOCK") || !strings.Contains(errs, "raijin-xss v"+version) {
		t.Errorf("banner missing or without the version: %q", errs)
	}
	if strings.Contains(out, "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	out, _ := replay(t)
	if n := strings.Count(out, "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	pretty, _ := replay(t, "--pretty")
	if !strings.Contains(pretty, "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty)
	}
	var a, b map[string]any
	if json.Unmarshal([]byte(out), &a) != nil || json.Unmarshal([]byte(pretty), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
}

func TestMissingEngineExitsTwoWithHint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-u", "https://a.example.com/?q=1", "--dalfox", "/nonexistent/dalfox"}, nil, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var v struct {
		Errors []struct{ Kind, Hint string }
		Raw    string
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || len(v.Errors) != 1 || v.Errors[0].Kind != "missing_engine" || !strings.Contains(v.Errors[0].Hint, "--dalfox") || v.Raw != "" {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestUsageErrorsExitOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--input", "../../testdata/sample.json"}, nil, &out, &errb); code != 1 {
		t.Errorf("no --scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-u", "https://out.of-scope.net/?q=1"}, nil, &out, &errb); code != 1 {
		t.Errorf("no target in scope: exit %d, want 1", code)
	}
}

func TestSummaryOriginAndOmitted(t *testing.T) {
	out, _ := replay(t, "-l", "../../testdata/targets.txt")
	if !strings.Contains(out, `"summary":"10 PoCs (6 verified, 3 reflected, 1 grep) at 8 locations: 5 findings (3 high, 1 medium, 1 low), 1 of 2 targets clean","origin":"http://app.example.com"`) {
		t.Errorf("summary: %s", out)
	}
	if !strings.Contains(out, `"payload":"'\"><iframe srcdoc=\"<input onauxclick=alert(1)>\" class=dalfox></iframe>"`) || strings.Contains(out, `\u003c`) || strings.Contains(out, `\u0026`) {
		t.Errorf("< and & should not be escaped: %s", out)
	}
	if !strings.Contains(out, `"groups":[{"id":"clean","locations":["/safe?q=a"]}]`) {
		t.Errorf("clean group: %s", out)
	}
	// one PoC and one target out of scope
	if !strings.Contains(out, `"omitted":{"duplicates":1,"out_of_scope":2}`) {
		t.Errorf("omitted: %s", out)
	}
}

func TestTargetsFromStdin(t *testing.T) {
	var out, errb bytes.Buffer
	args := []string{"--scope", scopeFile(t), "--input", "../../testdata/sample.json", "-l", "-"}
	if code := run(args, strings.NewReader("http://app.example.com/safe?q=a\n"), &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), `1 of 1 targets clean`) {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestTableFormat(t *testing.T) {
	out, _ := replay(t, "--format", "table")
	for _, want := range []string{"HIGH     q inHTML-URL (4)", "MEDIUM   cb inJS-single(1)-URL 3 payloads (1)", "LOW      grep dalfox-error-mysql1 (1)", "         /item/[1-3]?q="} {
		if !strings.Contains(out, want) {
			t.Errorf("table should contain %q:\n%s", want, out)
		}
	}
}

func TestBudgetIsCountedAndPointsToRaw(t *testing.T) {
	out, _ := replay(t, "--max-bytes", "1200")
	if len(out) > 1201 {
		t.Errorf("output is %d bytes", len(out))
	}
	var v struct {
		Omitted map[string]int
		Next    []string
		Budget  struct{ Truncated bool }
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil || !v.Budget.Truncated || v.Omitted["findings"] == 0 || len(v.Next) != 1 || !strings.Contains(v.Next[0], "sample.json") {
		t.Errorf("stdout = %s", out)
	}
}

// With only --scope, every host the scope names is tested as https://<host>/ and wildcards get a next step.
func TestScopeAloneTestsWhatTheScopeNames(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("example.com\n*.example.com\n10.0.0.0/30\n!10.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := filepath.Join(dir, "targets.txt")
	fake := filepath.Join(dir, "dalfox")
	script := "#!/bin/sh\n[ \"$1\" = file ] && cp \"$2\" " + got + "\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopePath, "--dalfox", fake, "--raw", filepath.Join(dir, "raw.json")}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(strings.Fields(string(b)), ",") != "https://example.com/,https://10.0.0.0/,https://10.0.0.2/,https://10.0.0.3/" {
		t.Errorf("dalfox got targets %q", b)
	}
	var res struct{ Next []string }
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Next) != 2 || !strings.Contains(res.Next[0], "raijin-subs --scope "+scopePath+" -d example.com") || !strings.Contains(res.Next[1], "raijin-crawl") {
		t.Errorf("next = %v", res.Next)
	}
}
