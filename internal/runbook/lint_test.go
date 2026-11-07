// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package runbook

import (
	"strings"
	"testing"
)

func TestLint(t *testing.T) {
	names := []string{"HOST", "CMD"}
	tests := []struct {
		name   string
		script string
		want   []Finding // nil means clean
	}{
		{"quoted passes", "echo \"$HOST\"\nprintf '%s' \"${HOST}\"\n", nil},
		{"single quoted literal passes", "echo '$HOST'\n", nil},
		{"undeclared var passes", "echo $OTHER\n", nil},
		{"comment ignored", "# eval $CMD\necho ok\n", nil},
		{"unquoted", "echo $HOST\n", []Finding{{RuleUnquoted, 1, "HOST"}}},
		{"unquoted braced", "ls ${HOST}\n", []Finding{{RuleUnquoted, 1, "HOST"}}},
		{"eval", "eval \"echo hi\"\n", []Finding{{RuleEval, 1, ""}}},
		{"eval after semicolon", "true; eval ls\n", []Finding{{RuleEval, 1, ""}}},
		{"evaluate word passes", "echo evaluate\n", nil},
		{"sh -c param", "sh -c \"echo $CMD\"\n", []Finding{{RuleShellC, 1, "CMD"}}},
		{"bash -c param", "bash -c \"$CMD\"\n", []Finding{{RuleShellC, 1, "CMD"}}},
		{"sh -c without param passes", "sh -c 'echo hi'\n", nil},
		{"source param", "source \"$CMD\"\n", []Finding{{RuleSourceParam, 1, "CMD"}}},
		{"dot param", ". \"$CMD\"\n", []Finding{{RuleSourceParam, 1, "CMD"}}},
		{"dot file passes", ". /etc/profile\n", nil},
		{"dollar paren wraps", "x=\"$(echo \"$HOST\")\"\n", []Finding{{RuleCommandSubst, 1, "HOST"}}},
		{"dollar paren no param passes", "x=$(date)\n", nil},
		{"backtick wraps", "x=`echo \"$HOST\"`\n", []Finding{{RuleCommandSubst, 1, "HOST"}}},
		{"line numbers", "echo a\n\necho $HOST\n", []Finding{{RuleUnquoted, 3, "HOST"}}},
		{"unterminated quote", "echo \"$HOST\n", []Finding{{RuleUntokenisable, 2, ""}}},
		{"unterminated subst", "x=$(echo hi\n", []Finding{{RuleUntokenisable, 1, ""}}},
		{"unterminated backtick", "x=`echo hi\n", []Finding{{RuleUntokenisable, 1, ""}}},
		{"nul byte", "echo\x00hi\n", []Finding{{RuleUntokenisable, 1, ""}}},
		{"invalid utf8", "echo \xff\n", []Finding{{RuleUntokenisable, 1, ""}}},
		{"undeclared in eval still flags eval", "eval \"echo $HOME\"\n", []Finding{{RuleEval, 1, ""}}},
		{"undeclared in sh -c passes", "sh -c \"$HOME\"\n", nil},
		{"escaped dollar parsed as escape", "echo \\$HOST\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Lint([]byte(tt.script), names)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("finding %d = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestLintBounds(t *testing.T) {
	big := []byte(strings.Repeat("a", MaxScriptBytes+1))
	if f := Lint(big, nil); len(f) != 1 || f[0].Rule != RuleUntokenisable {
		t.Errorf("oversize = %v", f)
	}
	many := []byte(strings.Repeat("echo $HOST\n", 500))
	f := Lint(many, []string{"HOST"})
	if len(f) > MaxLintFindings || f[len(f)-1].Rule != RuleTooManyFinding {
		t.Errorf("len=%d last=%v", len(f), f[len(f)-1])
	}
}

func TestFindingsNeverContainScript(t *testing.T) {
	f := Lint([]byte("echo $HOST canary-xyz\n"), []string{"HOST"})
	for _, x := range f {
		if strings.Contains(x.Rule+x.Param, "canary") {
			t.Error("finding leaks script text")
		}
	}
}

func TestCompileLint(t *testing.T) {
	d := baseDef(Parameter{Name: "HOST", Type: TypeString, Regex: "[a-z]+"})
	d.Script = []byte("echo $HOST\n")
	if _, err := Compile(d); err == nil {
		t.Fatal("unsafe script must be rejected by default")
	}
	c, err := Compile(d, WithLintPassMarker())
	if err != nil {
		t.Fatal(err)
	}
	if !c.LintMarkerUsed() {
		t.Error("marker use must be reported")
	}
	d.Script = []byte("echo \"$HOST\"\n")
	c, err = Compile(d, WithLintPassMarker())
	if err != nil || c.LintMarkerUsed() {
		t.Errorf("clean script: err=%v used=%v", err, c != nil && c.LintMarkerUsed())
	}
	// A script cannot set the marker itself.
	d.Script = []byte("# lint-pass-marker\necho $HOST\n")
	if _, err := Compile(d); err == nil {
		t.Error("in-script marker must not bypass lint")
	}
}
