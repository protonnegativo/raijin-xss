// Package reduce turns raw dalfox PoCs into a small, ranked Raijin result.
//
// It is lossless for what an agent acts on: every PoC dalfox reported is kept, with its type, parameter,
// injection context, method and CWE. PoCs of the same type, parameter and context share one finding
// that lists every URL they were found at, each with the first payload dalfox found there; the other
// payloads at a location are counted and stay in raw. Only exact duplicates are dropped. A byte budget
// can cut, but every cut is counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-xss/internal/dalfox"
	"github.com/protonnegativo/raijin-xss/internal/schema"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems int // 0 keeps every finding
	MaxBytes int
	InScope  func(target string) bool
	// Targets are the URLs dalfox tested, when they are known; the ones without a PoC become the
	// "clean" group.
	Targets []string
}

// Defaults keep every finding and cap the JSON at a size that fits comfortably in an agent's context.
func Defaults() Options {
	return Options{MaxBytes: 16000}
}

// Stats are the counts of the scan, before any budget, for the summary.
type Stats struct {
	PoCs      int            // distinct PoCs
	ByType    map[string]int // distinct PoCs per dalfox type (V, R, G)
	Locations int            // distinct locations over all findings
	Clean     int            // tested targets without a PoC
}

// Output is what Reduce returns.
type Output struct {
	Findings []schema.Finding
	Groups   []schema.Group
	Omitted  map[string]int
	// Origin is the scheme and host every URL shares, or "" when there are several.
	Origin string
	// Locations are every location per finding fingerprint, before any budget, for --state.
	Locations map[string][]string
	Stats     Stats
}

// typeRank maps a dalfox PoC type to a severity and a confidence.
var typeRank = map[string][2]string{
	"V": {"high", "verified"},
	"R": {"medium", "heuristic"},
	"G": {"low", ""},
}

type location struct {
	first dalfox.PoC // the first PoC dalfox reported here
	pocs  int
}

type entry struct {
	key, typ, param, context, grep, method, cwe string
	locs                                        map[string]*location // by location key
	order                                       []string
	pocs                                        int
}

// Reduce collapses PoCs into findings: one per type, parameter, context, method, CWE and grep pattern,
// listing every location with one payload.
func Reduce(pocs []dalfox.PoC, opt Options) Output {
	out := Output{Omitted: map[string]int{}, Locations: map[string][]string{}, Stats: Stats{ByType: map[string]int{}}}
	var kept []dalfox.PoC
	seen := map[dalfox.PoC]bool{}
	for _, p := range pocs {
		if opt.InScope != nil && !opt.InScope(p.Data) {
			out.Omitted["out_of_scope"]++
			continue
		}
		if seen[p] {
			out.Omitted["duplicates"]++
			continue
		}
		seen[p] = true
		kept = append(kept, p)
	}
	var targets []string
	for _, t := range opt.Targets {
		if opt.InScope == nil || opt.InScope(t) {
			targets = append(targets, t)
		}
	}

	origins := map[string]bool{}
	for _, p := range kept {
		origins[Origin(p.Data)] = true
	}
	for _, t := range targets {
		origins[Origin(t)] = true
	}
	if len(origins) == 1 {
		for o := range origins {
			out.Origin = o
		}
	}

	entries := map[string]*entry{}
	var keys []string
	hit := map[string]bool{} // scheme, host and path of every PoC, to find the clean targets
	for _, p := range kept {
		m := method(p.Method)
		grep := p.Grep()
		key := strings.Join([]string{p.Type, m, p.Param, p.InjectType, p.CWE, grep}, "\x00")
		e, ok := entries[key]
		if !ok {
			e = &entry{key: key, typ: p.Type, param: p.Param, context: p.InjectType, grep: grep, method: m, cwe: p.CWE,
				locs: map[string]*location{}}
			entries[key] = e
			keys = append(keys, key)
		}
		lk := m + " " + LocationKey(p)
		l, ok := e.locs[lk]
		if !ok {
			l = &location{first: p}
			e.locs[lk] = l
			e.order = append(e.order, lk)
		}
		l.pocs++
		e.pocs++
		out.Stats.PoCs++
		out.Stats.ByType[p.Type]++
		hit[stripQuery(p.Data)] = true
	}

	for _, key := range keys {
		e := entries[key]
		var locs []string
		byLoc := map[string]dalfox.PoC{} // written location -> the PoC kept there
		for _, lk := range e.order {
			l := e.locs[lk]
			u := l.first.Data
			if out.Origin != "" {
				u = strings.TrimPrefix(u, out.Origin)
			}
			u = escapeBrackets(u)
			locs = append(locs, u)
			byLoc[u] = l.first
		}
		locs = Compress(locs)
		first := byLoc[firstURL(locs[0])]
		rank, ok := typeRank[e.typ]
		if !ok {
			rank = [2]string{"info", ""}
		}
		id := ID(e)
		f := schema.Finding{ID: id, Severity: rank[0], Confidence: rank[1], Param: e.param, Grep: e.grep, CWE: e.cwe,
			Payload: first.Payload, Evidence: strings.TrimSpace(first.Evidence), Locations: locs, URLs: len(e.order),
			Fingerprint: fingerprint(key)}
		if e.context != "BUILTIN" {
			f.Context = e.context
		}
		if e.method != "GET" {
			f.Method = e.method
		}
		if e.payloadCountMatters() {
			f.Payloads = e.pocs
		}
		if e.typ == "G" && first.Payload == "toGrepping" {
			f.Payload = "" // dalfox's placeholder: the grep ran on a response, the PoC URL has the request
		}
		out.Locations[f.Fingerprint] = append([]string(nil), e.order...)
		out.Stats.Locations += len(e.order)
		out.Findings = append(out.Findings, f)
	}
	if out.Findings == nil {
		out.Findings = []schema.Finding{}
	}

	var clean []string
	cleanSeen := map[string]bool{}
	for _, t := range targets {
		if hit[stripQuery(t)] || cleanSeen[t] {
			continue
		}
		cleanSeen[t] = true
		if out.Origin != "" {
			t = strings.TrimPrefix(t, out.Origin)
		}
		clean = append(clean, escapeBrackets(t))
	}
	out.Groups = []schema.Group{}
	if len(clean) > 0 {
		out.Groups = append(out.Groups, schema.Group{ID: "clean", Locations: Compress(clean), URLs: len(clean)})
		out.Stats.Clean = len(clean)
	}

	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if schema.ConfidenceRank[a.Confidence] != schema.ConfidenceRank[b.Confidence] {
			return schema.ConfidenceRank[a.Confidence] > schema.ConfidenceRank[b.Confidence]
		}
		if a.URLs != b.URLs {
			return a.URLs > b.URLs
		}
		if a.Param != b.Param {
			return a.Param < b.Param
		}
		return a.ID < b.ID
	})

	if opt.MaxItems > 0 && len(out.Findings) > opt.MaxItems {
		out.Omitted["findings"] += len(out.Findings) - opt.MaxItems
		out.Findings = out.Findings[:opt.MaxItems]
	}
	return out
}

// payloadCountMatters is true when dalfox reported more than one PoC at a location, so the number of
// PoCs is not the number of locations.
func (e *entry) payloadCountMatters() bool {
	return e.pocs > len(e.order)
}

// LocationKey is where a PoC was found, without its payload: the PoC URL with the value of the injected
// query parameter removed. A grep match has no parameter, so its location is the URL without the query.
// A parameter that is not in the query (a path or body parameter) keeps the whole PoC URL.
func LocationKey(p dalfox.PoC) string {
	if p.Param == "" {
		return stripQuery(p.Data)
	}
	i := strings.Index(p.Data, "?")
	if i < 0 {
		return p.Data
	}
	base, q, frag := p.Data[:i], p.Data[i+1:], ""
	if j := strings.Index(q, "#"); j >= 0 {
		q, frag = q[:j], q[j:]
	}
	parts := strings.Split(q, "&")
	found := false
	for k, kv := range parts {
		name := strings.SplitN(kv, "=", 2)[0]
		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		}
		if name == p.Param {
			parts[k] = strings.SplitN(kv, "=", 2)[0] + "="
			found = true
		}
	}
	if !found {
		return p.Data
	}
	return base + "?" + strings.Join(parts, "&") + frag
}

// stripQuery is a URL without its query and fragment.
func stripQuery(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}

// ID is stable across runs while the type, parameter, context, method, CWE and grep pattern do not
// change: the PoC type in lowercase, the parameter (or grep pattern) and a short hash of the entry key.
func ID(e *entry) string {
	name := e.param
	if name == "" {
		name = e.grep
	}
	head := strings.ToLower(e.typ)
	if name != "" {
		head += "-" + name
	}
	return head + "-" + fingerprint(e.key)[:8]
}

// Origin is the scheme and host of a URL as dalfox wrote it ("http://127.0.0.1:19300"), or "" when the
// URL has none.
func Origin(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		return raw[:i+3+j]
	}
	return raw
}

var firstOfRange = regexp.MustCompile(`\[([0-9]+)[^\]]*\]`)

// firstURL is the first URL of a location: "/item/[3-5,9]?q=x" is "/item/3?q=x".
func firstURL(loc string) string {
	return firstOfRange.ReplaceAllString(loc, "$1")
}

// escapeBrackets writes a URL's own [ and ] as %5B and %5D, so a bracket in a location is always a range.
func escapeBrackets(s string) string {
	return strings.NewReplacer("[", "%5B", "]", "%5D").Replace(s)
}

var digitRun = regexp.MustCompile(`[0-9]+`)

// Compress writes URLs that differ in one number as one location with the numbers as ranges:
// "/item/1?q=x" ... "/item/20?q=x" is "/item/[1-20]?q=x". It tries each position of a number in the URLs
// (the first number, the second...) and keeps the one that gives the fewest locations. A number with a
// leading zero is never part of a range. The result is sorted.
func Compress(urls []string) []string {
	uniq := map[string]bool{}
	for _, u := range urls {
		uniq[u] = true
	}
	best := sorted(uniq)
	most := 0
	for _, u := range best {
		most = max(most, len(digitRun.FindAllStringIndex(u, -1)))
	}
	for pos := 0; pos < most; pos++ {
		if out := compressAt(best, pos); len(out) < len(best) {
			best = out
		}
	}
	return best
}

func compressAt(urls []string, pos int) []string {
	type run struct {
		prefix, suffix string
		nums           []int64
	}
	runs := map[string]*run{}
	var order []string
	var out []string
	for _, u := range urls {
		idx := digitRun.FindAllStringIndex(u, -1)
		if pos >= len(idx) {
			out = append(out, u)
			continue
		}
		a, b := idx[pos][0], idx[pos][1]
		digits := u[a:b]
		var n int64
		if len(digits) > 18 || (len(digits) > 1 && digits[0] == '0') {
			out = append(out, u)
			continue
		}
		fmt.Sscan(digits, &n)
		k := u[:a] + "\x00" + u[b:]
		r, ok := runs[k]
		if !ok {
			r = &run{prefix: u[:a], suffix: u[b:]}
			runs[k] = r
			order = append(order, k)
		}
		r.nums = append(r.nums, n)
	}
	for _, k := range order {
		r := runs[k]
		if len(r.nums) == 1 {
			out = append(out, fmt.Sprint(r.prefix, r.nums[0], r.suffix))
			continue
		}
		out = append(out, r.prefix+"["+ranges(r.nums)+"]"+r.suffix)
	}
	sort.Strings(out)
	return out
}

// ranges writes sorted numbers as "1-5,7,9-12".
func ranges(nums []int64) string {
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	var parts []string
	for i := 0; i < len(nums); {
		j := i
		for j+1 < len(nums) && nums[j+1] == nums[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", nums[i], nums[j]))
		} else {
			parts = append(parts, fmt.Sprint(nums[i]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// the clean group's locations, then the group, then the locations of the lowest-ranked findings (each
// keeps one, and its count), then the lowest-ranked findings. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		if len(g.Locations) == 0 {
			continue
		}
		before := size(g)
		res.Omitted["locations"] += len(g.Locations)
		g.Locations, g.Count = nil, g.URLs
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Locations) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(f.Locations) - 1
		f.Locations, f.Count = f.Locations[:1], f.URLs
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

func method(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	if m == "" {
		return "GET"
	}
	return m
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func sorted(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}
