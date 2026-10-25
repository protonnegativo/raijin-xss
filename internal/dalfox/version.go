package dalfox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	raijinxss "github.com/protonnegativo/raijin-xss"
)

// Engine is one entry of engines.json: the tested version and where to install it from.
type Engine struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`
	Pip     string `json:"pip,omitempty"`
	System  string `json:"system,omitempty"`
}

// Engines parses the embedded engines.json.
func Engines() (map[string]Engine, error) {
	var m map[string]Engine
	err := json.Unmarshal(raijinxss.Engines, &m)
	return m, err
}

// Install is the command that installs version v of the engine.
func (e Engine) Install(v string) string {
	switch {
	case e.Go != "":
		return "go install " + e.Go + "@v" + v
	case e.Pip != "":
		return "pipx install " + e.Pip + "==" + v
	default:
		return "install the " + e.System + " package, version " + v
	}
}

var versionRE = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// ParseVersion returns the first X.Y.Z in s ("v2.9.2" after dalfox's banner), or nil.
func ParseVersion(s string) []int {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	v := make([]int, 3)
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v
}

// Untested is true when installed has another major version than tested, or is older. Newer minor and
// patch versions of the same major are fine (the weekly drift job tests them), and so is a version
// that could not be parsed.
func Untested(installed, tested []int) bool {
	if installed == nil || tested == nil || installed[0] != tested[0] {
		return installed != nil && tested != nil
	}
	for i := 1; i < 3; i++ {
		if installed[i] != tested[i] {
			return installed[i] < tested[i]
		}
	}
	return false
}

// CheckVersion runs "dalfox version" (3s at most) and returns a hint when the installed dalfox is not
// the tested one, or "". It never fails the run.
func CheckVersion(ctx context.Context, bin string) string {
	engines, err := Engines()
	e, ok := engines["dalfox"]
	if err != nil || !ok {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "version")
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run()
	installed := ParseVersion(out.String())
	if !Untested(installed, ParseVersion(e.Version)) {
		return ""
	}
	return fmt.Sprintf("dalfox %d.%d.%d is not the tested %s; results may be incomplete. Install the tested version: %s, or run raijin-mcp update",
		installed[0], installed[1], installed[2], e.Version, e.Install(e.Version))
}
