// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package masking

import (
	"bytes"
	"testing"
)

func TestCompiledNewRedactor_OptionsCannotOverridePolicy(t *testing.T) {
	c, err := Compile([]Rule{{ID: "r1", Enabled: true, Detector: KindRegex, Regex: "SECRETVALUE", Replacement: "[X]", AppliesTo: Selectors{AllTargets: true}}}, SessionInfo{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	counted := 0
	// A caller trying to swap detectors/replacement must lose.
	r, err := c.NewRedactor(&out, WithOnRedact(func(string, int) { counted++ }), WithDetectors(), WithReplacement("leak"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = r.Write([]byte("a SECRETVALUE b"))
	_ = r.Close()
	if bytes.Contains(out.Bytes(), []byte("SECRETVALUE")) || bytes.Contains(out.Bytes(), []byte("leak")) || counted != 1 {
		t.Fatalf("out=%q counted=%d", out.String(), counted)
	}
}
