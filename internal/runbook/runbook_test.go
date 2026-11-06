// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package runbook

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func i64(n int64) *int64 { return &n }

func baseDef(ps ...Parameter) Definition {
	return Definition{Name: "restart", Interpreter: InterpreterPosixSh, Script: []byte("echo \"$HOST\"\n"), Parameters: ps}
}

func TestCompileRejects(t *testing.T) {
	str := Parameter{Name: "HOST", Type: TypeString, Regex: `[a-z.]+`}
	tests := []struct {
		name string
		def  Definition
	}{
		{"empty name", func() Definition { d := baseDef(); d.Name = ""; return d }()},
		{"bad interpreter", func() Definition { d := baseDef(); d.Interpreter = "powershell"; return d }()},
		{"empty script", func() Definition { d := baseDef(); d.Script = nil; return d }()},
		{"lowercase param", baseDef(Parameter{Name: "host", Type: TypeBool})},
		{"reserved PATH", baseDef(Parameter{Name: "PATH", Type: TypeBool})},
		{"reserved prefix", baseDef(Parameter{Name: "LD_FOO", Type: TypeBool})},
		{"duplicate", baseDef(str, str)},
		{"string without regex", baseDef(Parameter{Name: "HOST", Type: TypeString})},
		{"unbalanced regex escapes anchoring", baseDef(Parameter{Name: "HOST", Type: TypeString, Regex: `x)|(.*`})},
		{"bad regex", baseDef(Parameter{Name: "HOST", Type: TypeString, Regex: `(?=x)`})},
		{"enum without values", baseDef(Parameter{Name: "ENVNAME", Type: TypeEnum})},
		{"enum duplicate", baseDef(Parameter{Name: "ENVNAME", Type: TypeEnum, AllowedValues: []string{"a", "a"}})},
		{"int without bounds", baseDef(Parameter{Name: "N", Type: TypeInt})},
		{"int min>max", baseDef(Parameter{Name: "N", Type: TypeInt, Min: i64(5), Max: i64(1)})},
		{"unknown type", baseDef(Parameter{Name: "N", Type: "float"})},
		{"max_length over cap", baseDef(Parameter{Name: "HOST", Type: TypeString, Regex: `.*`, MaxLength: HardMaxLength + 1})},
		{"regex on int", baseDef(Parameter{Name: "N", Type: TypeInt, Min: i64(0), Max: i64(1), Regex: "x"})},
		{"invalid default", baseDef(Parameter{Name: "HOST", Type: TypeString, Regex: `[a-z]+`, HasDefault: true, Default: "UPPER"})},
		{"default without flag", baseDef(Parameter{Name: "HOST", Type: TypeString, Regex: `.*`, Default: "x"})},
		{"too many params", func() Definition {
			var ps []Parameter
			for i := 0; i <= MaxParameters; i++ {
				ps = append(ps, Parameter{Name: fmt.Sprintf("P%d", i), Type: TypeBool})
			}
			return baseDef(ps...)
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if c, err := Compile(tt.def); err == nil || c != nil {
				t.Fatalf("expected rejection, got %v", c)
			}
		})
	}
}

func TestDecodeStrict(t *testing.T) {
	if _, err := DecodeDefinition([]byte(`{"name":"a","bogus":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := DecodeDefinition([]byte(`{"name":"a"} {"x":1}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
	d, err := DecodeDefinition([]byte(`{"name":"a","interpreter":"sh","script":"ZWNobyBoaQ=="}`))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	if s := c.Selector(); s.AllTargets || len(s.TargetIDs) != 0 {
		t.Fatal("empty selector must select nothing")
	}
}

func compiled(t *testing.T) *Compiled {
	t.Helper()
	c, err := Compile(baseDef(
		Parameter{Name: "HOST", Type: TypeString, Regex: `[a-z0-9.-]+`, MaxLength: 16, Required: true},
		Parameter{Name: "MODE", Type: TypeEnum, AllowedValues: []string{"fast", "safe"}, HasDefault: true, Default: "safe"},
		Parameter{Name: "COUNT", Type: TypeInt, Min: i64(1), Max: i64(10)},
		Parameter{Name: "FORCE", Type: TypeBool},
	))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const canary = "CANARY-9f3a;$(id)`x`"

func TestValidate(t *testing.T) {
	c := compiled(t)
	v, err := c.Validate(map[string]string{"HOST": "db1.example.com", "COUNT": "3", "FORCE": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := v.Get("MODE"); m != "safe" {
		t.Fatalf("default not applied: %q", m)
	}
	if got := strings.Join(v.Names(), ","); got != "HOST,MODE,COUNT,FORCE" {
		t.Fatalf("names: %s", got)
	}
	bad := []struct {
		name string
		in   map[string]string
	}{
		{"missing required", map[string]string{}},
		{"undeclared", map[string]string{"HOST": "a", "EXTRA": "x"}},
		{"regex fail", map[string]string{"HOST": "A B"}},
		{"too long before regex", map[string]string{"HOST": strings.Repeat("a", 17)}},
		{"enum fail", map[string]string{"HOST": "a", "MODE": "turbo"}},
		{"int fail", map[string]string{"HOST": "a", "COUNT": "x"}},
		{"int range", map[string]string{"HOST": "a", "COUNT": "11"}},
		{"bool fail", map[string]string{"HOST": "a", "FORCE": "yes"}},
		{"NUL", map[string]string{"HOST": "a\x00b"}},
		{"newline", map[string]string{"HOST": "a\nb"}},
		{"partial match not allowed", map[string]string{"HOST": "a;b"}},
		{"invalid utf8", map[string]string{"HOST": "a\xffb"}},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := c.Validate(tt.in); !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
		})
	}
	if _, err := c.ValidatePairs([]Pair{{"HOST", "a"}, {"HOST", "b"}}); err == nil {
		t.Fatal("duplicate accepted")
	}
	var nilc *Compiled
	if _, err := nilc.Validate(nil); err == nil {
		t.Fatal("nil compiled accepted")
	}
}

func TestCanaryNeverInErrorsOrFormatting(t *testing.T) {
	c := compiled(t)
	for _, in := range []map[string]string{
		{"HOST": canary},
		{"HOST": "a", "MODE": canary},
		{"HOST": "a", "COUNT": canary},
		{"HOST": "a", "FORCE": canary},
		{"HOST": strings.Repeat("a", 17) + canary},
		{canary: "x"},
	} {
		_, err := c.Validate(in)
		if err == nil {
			t.Fatalf("expected error for %v", in)
		}
		if strings.Contains(err.Error(), "CANARY") || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "CANARY") {
			t.Fatalf("canary leaked in error: %v", err)
		}
	}
	v, err := c.Validate(map[string]string{"HOST": "canary-ok.ex"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%d"} {
		if out := fmt.Sprintf(f, v); strings.Contains(out, "canary-ok") {
			t.Fatalf("value leaked with %s: %s", f, out)
		}
	}
	if _, err := Compile(baseDef(Parameter{Name: "HOST", Type: TypeString, Regex: `[a-z]+`, HasDefault: true, Default: canary})); err == nil || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("default error missing or leaks: %v", err)
	}
}

func TestReservedList(t *testing.T) {
	for _, n := range []string{"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "IFS", "BASH_ENV", "ENV", "SHELLOPTS", "PS4", "PYTHONPATH", "HOME", "SHELL", "GCONV_PATH", "MALLOC_ARENA_MAX", "NODE_X", "TZ", "PS2"} {
		if !IsReservedName(n) {
			t.Errorf("%s not reserved", n)
		}
	}
	if IsReservedName("HOST") {
		t.Error("HOST reserved")
	}
}

func TestCompiledIsImmutable(t *testing.T) {
	min, max := int64(1), int64(5)
	vals := []string{"a", "b"}
	d := baseDef(
		Parameter{Name: "N", Type: TypeInt, Min: &min, Max: &max},
		Parameter{Name: "E", Type: TypeEnum, AllowedValues: vals},
	)
	c, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	max = 1000
	vals[0] = "evil"
	d.Parameters[0].Max = &max
	if _, err := c.Validate(map[string]string{"N": "500"}); err == nil {
		t.Fatal("caller mutation of Max changed validation")
	}
	if _, err := c.Validate(map[string]string{"E": "evil"}); err == nil {
		t.Fatal("caller mutation of AllowedValues changed validation")
	}
	if _, err := c.Validate(map[string]string{"E": "a", "N": "3"}); err != nil {
		t.Fatal(err)
	}
}
