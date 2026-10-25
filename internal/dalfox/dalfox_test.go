package dalfox

import (
	"strings"
	"testing"
)

func TestParseArrayWithEmptyObject(t *testing.T) {
	in := `[
{"type":"V","inject_type":"inHTML-URL","method":"GET","data":"http://a/s?q=%3Cb%3E","param":"q","payload":"<b>","cwe":"CWE-79"},
{"type":"G","inject_type":"BUILTIN","method":"GET","data":"http://a/r?id=%22","message_str":"Found dalfox-error-mysql1 via built-in grepping / payload: toGrepping"},
{}]`
	pocs, err := Parse(strings.NewReader(in))
	if err != nil || len(pocs) != 2 || pocs[0].Payload != "<b>" || pocs[1].Grep() != "dalfox-error-mysql1" || pocs[0].Grep() != "" {
		t.Errorf("pocs = %+v, err = %v", pocs, err)
	}
}

// A scan that was killed leaves an array without its end; every complete line is still read.
func TestParseCutOffArray(t *testing.T) {
	in := "[\n{\"type\":\"R\",\"data\":\"http://a/1\",\"param\":\"q\"},\n{\"type\":\"R\",\"data\":\"http://a/2\",\"param\":\"q\"},\n{\"type\":\"R\",\"da"
	pocs, err := Parse(strings.NewReader(in))
	if err != nil || len(pocs) != 2 {
		t.Errorf("pocs = %+v, err = %v", pocs, err)
	}
}

func TestParseEmpty(t *testing.T) {
	if pocs, err := Parse(strings.NewReader("")); err != nil || len(pocs) != 0 {
		t.Errorf("pocs = %+v, err = %v", pocs, err)
	}
}

func TestArgsNeverReachOut(t *testing.T) {
	args := strings.Join(Args("list.txt", Options{Workers: 10, RawPath: "raw.json", Headless: true, Mining: true, BAV: true}), " ")
	if args != "file list.txt --format json -o raw.json -S --no-spinner --no-color -w 10" {
		t.Errorf("args = %s", args)
	}
	for _, bad := range []string{"-b ", "--blind", "--remote", "--found-action"} {
		if strings.Contains(args, bad) {
			t.Errorf("args must not contain %s: %s", bad, args)
		}
	}
	off := strings.Join(Args("l", Options{RawPath: "r", Params: []string{"q"}, Extra: []string{"-H", "X: 1"}}), " ")
	if !strings.HasSuffix(off, "-p q --skip-headless --skip-mining-all --skip-bav -H X: 1") {
		t.Errorf("args = %s", off)
	}
}
