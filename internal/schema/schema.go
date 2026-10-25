// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engine found is dropped silently: every dalfox PoC is in a finding, as one of its
// locations or counted in its payloads, and anything a budget cuts is counted in Omitted. What an agent
// can rebuild is left out of the JSON to save tokens: empty lists, the budget when nothing was cut, a
// count equal to the locations listed, and fields at their documented default.
//
// raijin-xss adds the injection fields (param, context, method, cwe, grep, payload, evidence) to
// findings, and Origin to the result: they are what an agent reads to reproduce a PoC.
package schema

import (
	"bytes"
	"encoding/json"
)

// Marshal is json.Marshal without HTML escaping: "<" in a payload stays "<" instead of "<", and
// "&" in a URL stays "&", which costs tokens and nothing else.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Result is the top-level object a Raijin tool writes to stdout.
type Result struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Target  string `json:"target"`
	Summary string `json:"summary"`
	// Origin is the scheme and host every URL shares; locations are then written without it.
	Origin   string         `json:"origin,omitempty"`
	Findings []Finding      `json:"findings"`
	Groups   []Group        `json:"groups"`
	Omitted  map[string]int `json:"omitted,omitempty"`
	Errors   []Error        `json:"errors,omitempty"`
	Next     []string       `json:"next,omitempty"`
	// Raw is the file with the engine's full output, for details the result leaves out.
	Raw    string `json:"raw,omitempty"`
	Budget Budget `json:"budget"`
}

// MarshalJSON writes the budget only when something was cut.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	out := struct {
		plain
		Budget *Budget `json:"budget,omitempty"`
	}{plain: plain(r)}
	if r.Budget.Truncated {
		out.Budget = &r.Budget
	}
	return Marshal(out)
}

// Finding is one parameter and injection context with every URL dalfox found it at. dalfox's PoC type
// is the severity: V (verified) is high and verified, R (reflected) is medium and heuristic, G (grep)
// is low and matched. The same tool and ID in two runs is the same finding.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string `json:"confidence,omitempty"`
	// Param is the injected parameter; empty for a grep match, which dalfox ties to no parameter.
	Param string `json:"param,omitempty"`
	// Context is dalfox's inject_type: where the payload landed ("inHTML-none(1)-URL",
	// "inATTR-double(1)-URL", "inJS-single(1)-URL"). Left out for a grep match ("BUILTIN").
	Context string `json:"context,omitempty"`
	// Grep is the pattern a grep match matched ("dalfox-error-mysql1").
	Grep string `json:"grep,omitempty"`
	// Method is left out when it is GET.
	Method string `json:"method,omitempty"`
	CWE    string `json:"cwe,omitempty"`
	// Payload and Evidence are those of the first location: the payload dalfox injected there, and the
	// response line it landed in. Each location's own payload is in its PoC URL.
	Payload  string `json:"payload,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	// Locations are the PoC URLs, one per place the finding was found, with the payload dalfox found
	// first there. URLs that differ only in one number are one location with the numbers as a range.
	Locations []string `json:"locations"`
	// Payloads is the number of PoCs dalfox reported for the finding, written only when it reported
	// more than one at a location: the others are in raw.
	Payloads int `json:"payloads,omitempty"`
	// Count is the number of locations; it is set only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	// URLs is the number of locations, for ranking, the summary and Count; it is not written.
	URLs int `json:"-"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// Group is the targets dalfox tested and reported nothing for. It is only known when the targets are
// (a live run, or --input with -u or -l).
type Group struct {
	ID        string   `json:"id"`
	Locations []string `json:"locations,omitempty"`
	// Count is the number of targets; it is set only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	URLs  int `json:"-"`
}

// Error is a problem during the run, with a hint about what to try next.
type Error struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

// Budget reports the output limits that were applied.
type Budget struct {
	MaxItems  int  `json:"max_items"`
	MaxBytes  int  `json:"max_bytes"`
	Truncated bool `json:"truncated"`
}

// SeverityRank orders severities from most to least important.
var SeverityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
	"unknown":  0,
}

// ConfidenceRank orders confidence values: a verified finding before a matched one before a heuristic one.
var ConfidenceRank = map[string]int{
	"verified":  2,
	"":          1,
	"heuristic": 0,
}
