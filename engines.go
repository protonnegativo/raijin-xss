// Package raijinxss holds the files embedded from the repository root.
package raijinxss

import _ "embed"

// Engines is engines.json: the engine versions the fixtures in bench/fixtures were made with.
//
//go:embed engines.json
var Engines []byte
