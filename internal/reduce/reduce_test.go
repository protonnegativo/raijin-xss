package reduce

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-xss/internal/dalfox"
	"github.com/protonnegativo/raijin-xss/internal/schema"
)

func poc(typ, ctx, data, param, payload string) dalfox.PoC {
	return dalfox.PoC{Type: typ, InjectType: ctx, PoCType: "plain", Method: "GET", Data: data, Param: param,
		Payload: payload, Evidence: "2 line: " + payload, CWE: "CWE-79"}
}

func sample(t *testing.T) []dalfox.PoC {
	t.Helper()
	f, err := os.Open("../../testdata/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pocs, err := dalfox.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return pocs
}

func inScope(target string) bool { return !strings.Contains(target, "example.net") }

// Lossless: every PoC is a location of a finding or counted in its payloads.
func TestEveryPoCIsKeptOrCounted(t *testing.T) {
	out := Reduce(sample(t), Options{InScope: inScope})
	total := 0
	for _, f := range out.Findings {
		n := f.Payloads
		if n == 0 {
			n = f.URLs
		}
		total += n
	}
	if total != 10 || out.Omitted["duplicates"] != 1 || out.Omitted["out_of_scope"] != 1 {
		t.Errorf("PoCs accounted for = %d, omitted = %v; want 10 PoCs, 1 duplicate, 1 out of scope", total, out.Omitted)
	}
	if out.Stats.PoCs != 10 || out.Stats.ByType["V"] != 6 || out.Stats.ByType["R"] != 3 || out.Stats.ByType["G"] != 1 {
		t.Errorf("stats = %+v", out.Stats)
	}
}

// Collapse: the same param and context on many URLs is one finding that lists every URL with its payload.
func TestSameParamAndContextOnManyURLsIsOneFinding(t *testing.T) {
	var pocs []dalfox.PoC
	for i := 1; i <= 20; i++ {
		pocs = append(pocs, poc("V", "inHTML-none(1)-URL", fmt.Sprintf("http://a.example.com/item/%d?q=x%%3Csvg%%3E", i), "q", "<svg>"))
	}
	pocs = append(pocs, poc("V", "inHTML-none(1)-URL", "http://a.example.com/search?q=x%3Cimg%3E", "q", "<img>"))
	out := Reduce(pocs, Options{})
	if len(out.Findings) != 1 {
		t.Fatalf("findings = %+v", out.Findings)
	}
	f := out.Findings[0]
	want := []string{"/item/[1-20]?q=x%3Csvg%3E", "/search?q=x%3Cimg%3E"}
	if !reflect.DeepEqual(f.Locations, want) || f.URLs != 21 || f.Payloads != 0 || out.Origin != "http://a.example.com" {
		t.Errorf("locations = %v, urls = %d, payloads = %d, origin = %q", f.Locations, f.URLs, f.Payloads, out.Origin)
	}
}

// Many payloads at one location: one location with the first payload, the rest counted.
func TestManyPayloadsAtOneLocationAreCounted(t *testing.T) {
	var pocs []dalfox.PoC
	for i := 0; i < 71; i++ {
		pocs = append(pocs, poc("R", "inHTML-none(1)-URL", fmt.Sprintf("http://a.example.com/note?msg=a%%3Cp%d%%3E&x=1", i), "msg", fmt.Sprintf("<p%d>", i)))
	}
	out := Reduce(pocs, Options{})
	f := out.Findings[0]
	if len(f.Locations) != 1 || f.Locations[0] != "/note?msg=a%3Cp0%3E&x=1" || f.Payloads != 71 || f.Payload != "<p0>" {
		t.Errorf("finding = %+v", f)
	}
}

// Each context, type and CWE is its own finding: they are different bugs to act on.
func TestContextsTypesAndCWEsAreSeparate(t *testing.T) {
	u := "http://a.example.com/p?n=x"
	attr := poc("V", "inATTR-double(1)-URL", u, "n", "\">")
	attr.CWE = "CWE-83"
	pocs := []dalfox.PoC{poc("V", "inHTML-URL", u, "n", "<a>"), poc("V", "inJS-single(1)-URL", u, "n", "'"), poc("R", "inHTML-URL", u, "n", "<b>"), attr}
	out := Reduce(pocs, Options{})
	if len(out.Findings) != 4 {
		t.Fatalf("want 4 findings, got %+v", out.Findings)
	}
}

// Exact repeats collapse and are counted; a PoC that differs in anything else does not.
func TestOnlyExactDuplicatesCollapse(t *testing.T) {
	a := poc("V", "inHTML-URL", "http://a.example.com/s?q=1", "q", "<a>")
	b := a
	b.Evidence = "3 line: <a>"
	out := Reduce([]dalfox.PoC{a, a, b}, Options{})
	if out.Omitted["duplicates"] != 1 || out.Findings[0].Payloads != 2 {
		t.Errorf("omitted = %v, finding = %+v", out.Omitted, out.Findings[0])
	}
}

func TestTypesRankAsSeverityAndConfidence(t *testing.T) {
	out := Reduce(sample(t), Options{InScope: inScope})
	var got []string
	for _, f := range out.Findings {
		got = append(got, f.Severity+"/"+f.Confidence+"/"+f.ID[:2])
	}
	want := []string{"high/verified/v-", "high/verified/v-", "high/verified/v-", "medium/heuristic/r-", "low//g-"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if out.Findings[0].Param != "q" || out.Findings[0].URLs != 4 {
		t.Errorf("the finding with the most locations should rank first among equals: %+v", out.Findings[0])
	}
}

// A grep match names its pattern, has no context, no placeholder payload, and its location is its PoC URL.
func TestGrepMatch(t *testing.T) {
	g := dalfox.PoC{Type: "G", InjectType: "BUILTIN", Method: "GET", Data: "http://a.example.com/report?id=%22", Payload: "toGrepping",
		MessageStr: "Found dalfox-error-mysql1 via built-in grepping / payload: toGrepping"}
	g2 := g
	g2.Data = "http://a.example.com/report?id=%27"
	out := Reduce([]dalfox.PoC{g, g2}, Options{})
	f := out.Findings[0]
	if f.Grep != "dalfox-error-mysql1" || f.Context != "" || f.Payload != "" || f.Severity != "low" || f.Confidence != "" ||
		!strings.HasPrefix(f.ID, "g-dalfox-error-mysql1-") || len(f.Locations) != 1 || f.Payloads != 2 {
		t.Errorf("finding = %+v", f)
	}
}

// A PoC verified in headless Chrome has no payload field: its PoC URL still carries it.
func TestHeadlessPoCWithoutPayloadKeepsItsURL(t *testing.T) {
	p := poc("V", "inJS-single(1)-URL", "http://a.example.com/w?cb=a%27%3Balert(1)%2F%2F", "cb", "")
	p.Evidence = ""
	f := Reduce([]dalfox.PoC{p}, Options{}).Findings[0]
	if f.Payload != "" || f.Evidence != "" || len(f.Locations) != 1 || f.Locations[0] != "/w?cb=a%27%3Balert(1)%2F%2F" {
		t.Errorf("finding = %+v", f)
	}
}

func TestOutOfScopeIsDroppedAndCounted(t *testing.T) {
	pocs := []dalfox.PoC{poc("V", "inHTML-URL", "http://a.example.com/s?q=1", "q", "<a>"), poc("V", "inHTML-URL", "http://b.example.net/s?q=1", "q", "<a>")}
	out := Reduce(pocs, Options{InScope: inScope, Targets: []string{"http://b.example.net/x"}})
	if len(out.Findings) != 1 || out.Findings[0].URLs != 1 || out.Omitted["out_of_scope"] != 1 || len(out.Groups) != 0 {
		t.Errorf("out = %+v", out)
	}
}

func TestCleanTargetsAreAGroup(t *testing.T) {
	out := Reduce(sample(t), Options{InScope: inScope, Targets: []string{"http://app.example.com/search?q=a", "http://app.example.com/safe?q=a", "http://app.example.com/api/echo?msg=a"}})
	if len(out.Groups) != 1 || out.Groups[0].ID != "clean" || !reflect.DeepEqual(out.Groups[0].Locations, []string{"/api/echo?msg=a", "/safe?q=a"}) || out.Stats.Clean != 2 {
		t.Errorf("groups = %+v", out.Groups)
	}
}

func TestLocationKey(t *testing.T) {
	cases := []struct{ data, param, want string }{
		{"http://a/p?q=x%3Cb%3E&s=1", "q", "http://a/p?q=&s=1"},
		{"http://a/p?s=1&q=x", "q", "http://a/p?s=1&q="},
		{"http://a/p?s=1#f", "q", "http://a/p?s=1#f"}, // not in the query: the whole PoC URL
		{"http://a/p/x%3Cb%3E", "path", "http://a/p/x%3Cb%3E"},
		{"http://a/r?id=%22", "", "http://a/r"},
	}
	for _, c := range cases {
		if got := LocationKey(dalfox.PoC{Data: c.data, Param: c.param}); got != c.want {
			t.Errorf("LocationKey(%q, %q) = %q, want %q", c.data, c.param, got, c.want)
		}
	}
}

func TestIDIsStableAndIgnoresURLs(t *testing.T) {
	a := Reduce([]dalfox.PoC{poc("V", "inHTML-URL", "http://a.example.com/s?q=1", "q", "<a>")}, Options{}).Findings[0]
	b := Reduce([]dalfox.PoC{poc("V", "inHTML-URL", "http://a.example.com/t?q=2", "q", "<b>")}, Options{}).Findings[0]
	if a.ID != b.ID || a.ID != "v-q-cc55ed8d" {
		t.Errorf("ids %q and %q", a.ID, b.ID)
	}
}

func TestBracketsInURLsAreEscaped(t *testing.T) {
	f := Reduce([]dalfox.PoC{poc("R", "inHTML-URL", "http://a.example.com/s?q=[1]", "q", "[1]")}, Options{}).Findings[0]
	if f.Locations[0] != "/s?q=%5B1%5D" {
		t.Errorf("locations = %v", f.Locations)
	}
}

func TestMaxItemsIsCounted(t *testing.T) {
	out := Reduce(sample(t), Options{InScope: inScope, MaxItems: 2})
	if len(out.Findings) != 2 || out.Omitted["findings"] != 3 {
		t.Errorf("findings = %d, omitted = %v", len(out.Findings), out.Omitted)
	}
}

func TestFitCutsLeastImportantFirstAndCounts(t *testing.T) {
	var pocs []dalfox.PoC
	var targets []string
	for i := 1; i <= 30; i++ {
		pocs = append(pocs, poc("R", "inHTML-URL", fmt.Sprintf("http://a.example.com/p%d?q=%%3Ca%d%%3E", i*7, i), "q", fmt.Sprintf("<a%d>", i)))
		targets = append(targets, fmt.Sprintf("http://a.example.com/clean%d/x%d", i*3, i))
	}
	pocs = append(pocs, poc("V", "inHTML-URL", "http://a.example.com/s?q=%3Cb%3E", "q", "<b>"))
	out := Reduce(pocs, Options{Targets: targets})
	res := schema.Result{Findings: out.Findings, Groups: out.Groups, Omitted: out.Omitted, Budget: schema.Budget{MaxBytes: 700}}
	Fit(&res, 700)
	b, _ := schema.Marshal(res)
	if len(b) > 700 || !res.Budget.Truncated {
		t.Fatalf("size %d, truncated %v: %s", len(b), res.Budget.Truncated, b)
	}
	if len(res.Groups) != 0 || res.Omitted["groups"] != 1 || res.Findings[0].Severity != "high" {
		t.Errorf("groups should go first and the verified finding stay: %s", b)
	}
	if f := res.Findings[len(res.Findings)-1]; f.Severity == "medium" && (len(f.Locations) != 1 || f.Count != 30) {
		t.Errorf("a cut finding keeps one location and its count: %+v", f)
	}
}

func TestCompress(t *testing.T) {
	got := Compress([]string{"/u/1?a=2", "/u/2?a=2", "/u/3?a=2", "/u/7?a=2", "/u/007?a=2", "/v"})
	want := []string{"/u/007?a=2", "/u/[1-3,7]?a=2", "/v"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
