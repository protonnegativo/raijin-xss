// Command raijin-xss runs dalfox and returns a small, collapsed, ranked result for AI agents.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"

	"github.com/protonnegativo/raijin-xss/internal/banner"
	"github.com/protonnegativo/raijin-xss/internal/dalfox"
	"github.com/protonnegativo/raijin-xss/internal/reduce"
	"github.com/protonnegativo/raijin-xss/internal/schema"
	"github.com/protonnegativo/raijin-xss/internal/scope"
	"github.com/protonnegativo/raijin-xss/internal/state"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-xss", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var targets, params multi
	fs.Var(&targets, "u", "target URL with its parameters (repeatable; default: every host the scope names, as https://<host>/)")
	list := fs.String("l", "", "file with one target URL per line (- reads stdin)")
	scopeFile := fs.String("scope", "", "scope file (required): domains, *.wildcards, IPs, CIDRs, !exclusions")
	fs.Var(&params, "p", "only test this parameter (repeatable, dalfox -p)")
	workers := fs.Int("workers", 10, "concurrent workers (dalfox -w; dalfox's own default is 100)")
	delay := fs.Int("delay", 0, "milliseconds between requests to the same host (dalfox --delay)")
	timeout := fs.Int("timeout", 0, "request timeout in seconds")
	headless := fs.Bool("headless", true, "use headless Chrome for DOM XSS and to verify payloads in JS (false: dalfox --skip-headless)")
	mining := fs.Bool("mining", true, "mine more parameters from a dictionary and the DOM (false: dalfox --skip-mining-all)")
	bav := fs.Bool("bav", true, "also send SQLi, SSTI, open redirect and CRLF payloads for grep matches (false: dalfox --skip-bav)")
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", reduce.Defaults().MaxBytes, "maximum size of the JSON output; cuts are counted in omitted")
	rawPath := fs.String("raw", "", "file for dalfox's full JSON output (default: a new file in the temp dir)")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	input := fs.String("input", "", "read an existing dalfox JSON file instead of running dalfox (-u/-l then name the tested targets)")
	bin := fs.String("dalfox", "dalfox", "path to the dalfox binary")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-xss --scope scope.txt [-u url | -l urls.txt | --input dalfox.json] [flags] [-- extra dalfox args]\n\nWith no targets it tests every host the scope names (as https://<host>/).\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-xss", strings.TrimPrefix(version, "v"), useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, versionLine())
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-xss: --scope is required")
		return 1
	}
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		fmt.Fprintln(stderr, "raijin-xss: scope:", err)
		return 1
	}

	res := schema.Result{
		Tool:     "raijin-xss",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}

	if *list != "" {
		lines, err := readLines(*list, stdin)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-xss:", err)
			return 1
		}
		targets = append(targets, lines...)
	}
	var inScope []string
	if len(targets) == 0 && *input == "" {
		// no targets given: test what the scope names. dalfox needs URLs, so each host becomes
		// https://<host>/ and parameter mining finds what it can from there.
		hosts, wildcards, ranges := sc.Targets()
		for _, h := range hosts {
			if strings.Contains(h, ":") {
				h = "[" + h + "]"
			}
			inScope = append(inScope, "https://"+h+"/")
		}
		for _, w := range wildcards {
			res.Next = append(res.Next, "raijin-subs --scope "+*scopeFile+" -d "+strings.TrimPrefix(w, "*.")+", then raijin-xss -l <urls> to cover "+w)
		}
		for _, r := range ranges {
			res.Next = append(res.Next, "raijin-ports --scope "+*scopeFile+" -host "+r+", then raijin-xss -l <urls> to cover "+r)
		}
		if len(inScope) == 0 {
			res.Summary = "the scope names no single host to scan"
			res.Target = *scopeFile
			write(stdout, &res, *format, *pretty)
			return 1
		}
		res.Next = append(res.Next, "raijin-crawl or raijin-params --scope "+*scopeFile+" to find URLs with parameters, then raijin-xss -l <urls>")
	} else {
		inScope = filter(targets, sc, res.Omitted)
	}

	var pocs []dalfox.PoC
	var parsed dalfox.Format
	if *input != "" {
		f, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-xss:", err)
			return 1
		}
		pocs, parsed, err = dalfox.ParseFormat(f)
		f.Close()
		if err != nil {
			fmt.Fprintln(stderr, "raijin-xss:", err)
			return 1
		}
		res.Target = *input
	} else {
		if len(inScope) == 0 {
			fmt.Fprintln(stderr, "raijin-xss: no targets in scope")
			return 1
		}
		res.Target = targetSummary(inScope, res.Omitted["out_of_scope"])

		tempRaw := *rawPath == ""
		if tempRaw {
			f, err := os.CreateTemp("", "raijin-xss-*.json")
			if err != nil {
				fmt.Fprintln(stderr, "raijin-xss:", err)
				return 1
			}
			f.Close()
			*rawPath = f.Name()
		}
		res.Raw = *rawPath

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if path, err := exec.LookPath(*bin); err == nil {
			if hint := dalfox.CheckVersion(ctx, path); hint != "" {
				res.Errors = append(res.Errors, schema.Error{Kind: "engine_version", Hint: hint})
			}
		}
		var stderrTail string
		pocs, parsed, stderrTail, err = dalfox.Run(ctx, inScope, dalfox.Options{
			Binary: *bin, Workers: *workers, Delay: *delay, Timeout: *timeout, Params: params,
			Headless: *headless, Mining: *mining, BAV: *bav, Extra: fs.Args(), RawPath: *rawPath,
		})
		switch {
		case errors.Is(err, dalfox.ErrNotFound):
			res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install dalfox (go install github.com/hahwul/dalfox/v2@latest) or pass --dalfox <path>, or run raijin-mcp update"})
			res.Summary = "dalfox not found, nothing scanned"
			res.Raw = ""
			if tempRaw {
				os.Remove(*rawPath)
			}
			write(stdout, &res, *format, *pretty)
			return 2
		case err != nil:
			hint := err.Error()
			if stderrTail != "" {
				hint += ": " + stderrTail
			}
			res.Errors = append(res.Errors, schema.Error{Kind: "engine_error", Hint: hint})
		}
	}

	if parsed.Bad > 0 {
		// results the reducer cannot use are not in findings: count them, and say why
		res.Omitted["unparsed"] += parsed.Bad
		res.Errors = append(res.Errors, schema.Error{Kind: "engine_format", Hint: fmt.Sprintf(
			"%d of %d dalfox results had no type and data; the engine's output format may have changed. Read %s for the full output",
			parsed.Bad, parsed.Results, res.Raw+*input)})
	}

	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.InScope = sc.Allowed
	opt.Targets = inScope
	out := reduce.Reduce(pocs, opt)
	res.Findings, res.Groups, res.Origin = out.Findings, out.Groups, out.Origin
	for k, v := range out.Omitted {
		res.Omitted[k] += v
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = st.Mark(res.Findings, out.Locations)
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	res.Summary = summary(res, out.Stats, len(inScope), newCount)
	if res.Omitted["findings"] > 0 {
		res.Budget.Truncated = true
	}
	reduce.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		hint := "raise --max-bytes"
		if src := res.Raw + *input; src != "" {
			hint += " or read " + src + " for what was cut"
		}
		res.Next = append(res.Next, hint)
		reduce.Fit(&res, *maxBytes) // the hint takes room too
	}
	write(stdout, &res, *format, *pretty)
	return 0
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func filter(targets []string, sc *scope.Scope, omitted map[string]int) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		if !sc.Allowed(t) {
			omitted["out_of_scope"]++
			continue
		}
		out = append(out, t)
	}
	return out
}

func targetSummary(targets []string, skipped int) string {
	s := fmt.Sprintf("%d target(s)", len(targets))
	if len(targets) == 1 {
		s = targets[0]
	}
	if skipped > 0 {
		s += fmt.Sprintf(" (%d out of scope skipped)", skipped)
	}
	return s
}

// summary is written before the budget, so it stays true when Fit cuts.
func summary(res schema.Result, st reduce.Stats, tested, newCount int) string {
	var kinds []string
	for _, k := range []struct{ typ, name string }{{"V", "verified"}, {"R", "reflected"}, {"G", "grep"}} {
		if n := st.ByType[k.typ]; n > 0 {
			kinds = append(kinds, fmt.Sprintf("%d %s", n, k.name))
		}
	}
	s := fmt.Sprintf("%d PoCs", st.PoCs)
	if len(kinds) > 0 {
		s += " (" + strings.Join(kinds, ", ") + ")"
	}
	bySev := map[string]int{}
	for _, f := range res.Findings {
		bySev[f.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s += fmt.Sprintf(" at %d locations: %d findings", st.Locations, len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	if tested > 0 {
		s += fmt.Sprintf(", %d of %d targets clean", st.Clean, tested)
	}
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		if res.Origin != "" {
			fmt.Fprintln(w, "origin  ", res.Origin)
		}
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			fmt.Fprintf(w, "%-8s %s (%d)%s\n", strings.ToUpper(f.Severity), describe(f), f.URLs, mark)
			for _, l := range f.Locations {
				fmt.Fprintf(w, "         %s\n", l)
			}
		}
		for _, g := range res.Groups {
			fmt.Fprintf(w, "%-8s %d targets\n", g.ID, g.URLs)
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(res)
}

// describe is a one-line view of a finding for the table: param, context or grep pattern, method.
func describe(f schema.Finding) string {
	var parts []string
	if f.Method != "" {
		parts = append(parts, f.Method)
	}
	if f.Param != "" {
		parts = append(parts, f.Param)
	}
	if f.Context != "" {
		parts = append(parts, f.Context)
	}
	if f.Grep != "" {
		parts = append(parts, "grep "+f.Grep)
	}
	if f.Payloads > 0 {
		parts = append(parts, fmt.Sprintf("%d payloads", f.Payloads))
	}
	return strings.Join(parts, " ")
}

func readLines(path string, stdin io.Reader) ([]string, error) {
	var r io.Reader = stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
