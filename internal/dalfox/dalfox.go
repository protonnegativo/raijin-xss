// Package dalfox runs the dalfox XSS scanner and parses its JSON output.
package dalfox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ErrNotFound is returned when the dalfox binary is not on PATH.
var ErrNotFound = errors.New("dalfox binary not found")

// PoC is one dalfox result: a payload that was verified (V), reflected (R) or matched a grep pattern
// (G) at one URL.
type PoC struct {
	// Type is V (verified: dalfox found the injected element in the DOM, or a dialog fired in headless
	// Chrome), R (reflected: the payload came back unencoded but did not run) or G (grep: the response
	// matched a pattern such as a SQL error, with or without a parameter).
	Type string `json:"type"`
	// InjectType is where the payload landed: "inHTML-none(1)-URL", "inATTR-double(1)-URL",
	// "inJS-single(1)-URL", "BUILTIN" for a grep match.
	InjectType string `json:"inject_type"`
	PoCType    string `json:"poc_type"`
	Method     string `json:"method"`
	// Data is the PoC: the URL with the payload in the parameter.
	Data     string `json:"data"`
	Param    string `json:"param"`
	Payload  string `json:"payload"`
	Evidence string `json:"evidence"`
	CWE      string `json:"cwe"`
	Severity string `json:"severity"`
	// MessageStr is dalfox's log line; for a grep match it names the pattern.
	MessageStr string `json:"message_str"`
}

// Grep is the name of the pattern a grep match matched ("dalfox-error-mysql1"), or "".
func (p PoC) Grep() string {
	const pre = "Found "
	m := p.MessageStr
	if p.Type != "G" || !strings.HasPrefix(m, pre) {
		return ""
	}
	m = m[len(pre):]
	if i := strings.Index(m, " via "); i >= 0 {
		return m[:i]
	}
	return ""
}

// Options are the dalfox settings Raijin passes through.
type Options struct {
	Binary string
	// Workers is dalfox -w; dalfox's own default is 100.
	Workers int
	Delay   int // milliseconds between requests to the same host
	Timeout int // seconds
	Params  []string
	// Headless false skips the headless Chrome checks (DOM XSS, and verifying payloads in JS).
	Headless bool
	// Mining false skips parameter mining (dictionary and DOM).
	Mining bool
	// BAV false skips the basic other-vulnerability checks (SQLi, SSTI, open redirect, CRLF payloads).
	BAV   bool
	Extra []string
	// RawPath receives dalfox's JSON output unchanged (-o). It is required.
	RawPath string
}

// Run scans the targets and returns every PoC, the format counts (see Format), plus the last stderr
// lines if dalfox failed.
func Run(ctx context.Context, targets []string, opt Options) ([]PoC, Format, string, error) {
	var format Format
	bin := opt.Binary
	if bin == "" {
		bin = "dalfox"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, format, "", ErrNotFound
	}

	list, err := os.CreateTemp("", "raijin-xss-targets-*.txt")
	if err != nil {
		return nil, format, "", err
	}
	defer os.Remove(list.Name())
	if _, err := io.WriteString(list, strings.Join(targets, "\n")+"\n"); err != nil {
		list.Close()
		return nil, format, "", err
	}
	list.Close()

	// dalfox appends to -o, so a file left by an earlier run is emptied first.
	if err := os.WriteFile(opt.RawPath, nil, 0o644); err != nil {
		return nil, format, "", err
	}

	// dalfox writes the same JSON to stdout and to -o; raijin-xss reads the file. Stdin stays nil
	// (/dev/null) so a caller's pipe is never read as a target list.
	cmd := exec.CommandContext(ctx, path, Args(list.Name(), opt)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	waitErr := cmd.Run()
	f, err := os.Open(opt.RawPath)
	if err != nil {
		if waitErr != nil {
			return nil, format, tail(stderr.String(), 3), fmt.Errorf("dalfox exited: %w", waitErr)
		}
		return nil, format, "", nil // no PoC: dalfox may not write the file at all
	}
	defer f.Close()
	pocs, format, parseErr := ParseFormat(f)
	if parseErr != nil {
		return pocs, format, tail(stderr.String(), 3), parseErr
	}
	if waitErr != nil {
		return pocs, format, tail(stderr.String(), 3), fmt.Errorf("dalfox exited: %w", waitErr)
	}
	return pocs, format, "", nil
}

// Args builds the dalfox command line: file mode, JSON written to RawPath, silent, no colors. It never
// adds a blind callback (-b), remote payloads or remote wordlists: nothing leaves the target.
func Args(listFile string, opt Options) []string {
	args := []string{"file", listFile, "--format", "json", "-o", opt.RawPath, "-S", "--no-spinner", "--no-color"}
	if opt.Workers > 0 {
		args = append(args, "-w", fmt.Sprint(opt.Workers))
	}
	if opt.Delay > 0 {
		args = append(args, "--delay", fmt.Sprint(opt.Delay))
	}
	if opt.Timeout > 0 {
		args = append(args, "--timeout", fmt.Sprint(opt.Timeout))
	}
	for _, p := range opt.Params {
		args = append(args, "-p", p)
	}
	if !opt.Headless {
		args = append(args, "--skip-headless")
	}
	if !opt.Mining {
		args = append(args, "--skip-mining-all")
	}
	if !opt.BAV {
		args = append(args, "--skip-bav")
	}
	return append(args, opt.Extra...)
}

// Format counts the results Parse read and how many of them lacked the fields the reducer needs (type
// and data) or were not JSON at all: a sign that dalfox's output format changed.
type Format struct {
	Results int
	Bad     int
}

// Parse reads dalfox JSON: an array of PoCs, with an empty object dalfox adds at the end. JSON lines
// (one PoC per line) are read too. Objects without a type or data are skipped.
func Parse(r io.Reader) ([]PoC, error) {
	pocs, _, err := ParseFormat(r)
	return pocs, err
}

// ParseFormat is Parse, and also counts the results that were skipped (see Format).
func ParseFormat(r io.Reader) ([]PoC, Format, error) {
	var f Format
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, f, err
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, f, nil
	}
	var pocs []PoC
	add := func(obj []byte) {
		if string(bytes.Join(bytes.Fields(obj), nil)) == "{}" {
			return // dalfox's closing empty object
		}
		f.Results++
		var p PoC
		if err := json.Unmarshal(obj, &p); err != nil || p.Type == "" || p.Data == "" {
			f.Bad++
			return
		}
		pocs = append(pocs, p)
	}
	if b[0] == '[' {
		var all []json.RawMessage
		if err := json.Unmarshal(b, &all); err == nil {
			for _, obj := range all {
				add(obj)
			}
			return pocs, f, nil
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	for sc.Scan() {
		line := bytes.TrimRight(bytes.TrimSpace(sc.Bytes()), ",")
		line = bytes.TrimSpace(bytes.TrimLeft(bytes.TrimRight(line, "]"), "["))
		if len(line) == 0 {
			continue
		}
		add(line) // a line that is not JSON counts as a bad result
	}
	return pocs, f, sc.Err()
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
