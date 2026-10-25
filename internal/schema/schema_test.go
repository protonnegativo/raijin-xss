package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-xss",
		Findings: []Finding{{ID: "g-x-ab12cd34", Severity: "low", Locations: []string{"/r?id=%22"}, URLs: 1, Fingerprint: "fp"}},
		Groups:   []Group{},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "urls", "confidence", "param", "context", "grep", "method", "cwe", "payload", "evidence", "payloads", "new", "origin", "omitted", "errors", "next", "raw", "budget"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
}

func TestPayloadsAreNotEscaped(t *testing.T) {
	f := Finding{ID: "v-q-x", Severity: "high", Confidence: "verified", Param: "q", Context: "inHTML-URL", CWE: "CWE-79", Payload: "<svg onload=alert(1)>", Locations: []string{"/s?q=%3Csvg%3E&x=1"}, URLs: 1}
	b, _ := Marshal(f)
	want := `{"id":"v-q-x","severity":"high","confidence":"verified","param":"q","context":"inHTML-URL","cwe":"CWE-79","payload":"<svg onload=alert(1)>","locations":["/s?q=%3Csvg%3E&x=1"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "r-q-x", Locations: []string{"/a?q=1"}, Payloads: 40, Count: 7, URLs: 7}},
		Groups:   []Group{{ID: "clean", Count: 4, URLs: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["/a?q=1"],"payloads":40,"count":7`) || !strings.Contains(s, `{"id":"clean","count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
}
