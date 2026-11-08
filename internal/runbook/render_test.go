// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbook

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func renderDef(t *testing.T) *Compiled {
	t.Helper()
	d := baseDef(
		Parameter{Name: "HOST", Type: TypeString, Regex: ".*", MaxLength: 256},
		Parameter{Name: "N", Type: TypeInt, Min: i64(0), Max: i64(10)},
	)
	c, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func envNames(env []string) []string {
	var out []string
	for _, e := range env {
		out = append(out, e[:strings.IndexByte(e, '=')])
	}
	return out
}

func TestRenderGolden(t *testing.T) {
	c := renderDef(t)
	benign, err := c.Validate(map[string]string{"HOST": "web1", "N": "3"})
	if err != nil {
		t.Fatal(err)
	}
	base, err := Render(c, benign)
	if err != nil {
		t.Fatal(err)
	}
	evil := []string{
		"a;rm -rf /", "a'b\"c", "$(id)", "`id`", "a b c", "x' OR '1'='1", "${IFS}", "a|b&c>d", "-rf", "\\", "x'; DROP TABLE t;--",
	}
	for _, e := range evil {
		v, err := c.Validate(map[string]string{"HOST": e, "N": "3"})
		if err != nil {
			t.Fatalf("validate %q: %v", e, err)
		}
		got, err := Render(c, v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Script, base.Script) {
			t.Errorf("script differs for %q", e)
		}
		if !reflect.DeepEqual(got.Args, base.Args) {
			t.Errorf("args differ for %q", e)
		}
		if !reflect.DeepEqual(envNames(got.Env), envNames(base.Env)) {
			t.Errorf("env names differ for %q", e)
		}
		if got.Env[0] != EnvPrefix+"HOST="+e {
			t.Errorf("env value not passed verbatim for %q", e)
		}
	}
	if !bytes.Equal(base.Script, c.def.Script) {
		t.Error("script not byte-identical to pinned script")
	}
}

// Newlines are control characters: the validator rejects them, and Render
// rejects them again if a corrupt Validated reaches it.
func TestRenderRejectsNewline(t *testing.T) {
	c := renderDef(t)
	if _, err := c.Validate(map[string]string{"HOST": "a\nb"}); err == nil {
		t.Error("validator must reject newline")
	}
	bad := Validated{vals: map[string]string{"HOST": "a\nb"}, order: []string{"HOST"}}
	if _, err := Render(c, bad); !errors.Is(err, ErrRender) {
		t.Errorf("render must reject newline, err=%v", err)
	}
}

func TestRenderCopiesScript(t *testing.T) {
	c := renderDef(t)
	v, _ := c.Validate(map[string]string{"HOST": "h"})
	inv, _ := Render(c, v)
	inv.Script[0] = 'X'
	if c.def.Script[0] == 'X' {
		t.Error("render aliases the compiled script")
	}
}

func TestRenderNamespacedEnv(t *testing.T) {
	c := renderDef(t)
	v, _ := c.Validate(map[string]string{"HOST": "h", "N": "1"})
	inv, _ := Render(c, v)
	for _, n := range envNames(inv.Env) {
		if !strings.HasPrefix(n, EnvPrefix) || IsReservedName(n) {
			t.Errorf("env name %q not safely namespaced", n)
		}
	}
	// Even a reserved-looking name cannot escape the prefix.
	if IsReservedName(EnvPrefix + "PATH") {
		t.Log("prefixed name is reserved; still namespaced")
	}
}

func TestRenderCanary(t *testing.T) {
	c := renderDef(t)
	canary := "canary-value-Zk39qLw"
	v, _ := c.Validate(map[string]string{"HOST": canary})
	inv, err := Render(c, v)
	if err != nil {
		t.Fatal(err)
	}
	out := fmt.Sprintf("%v|%+v|%#v|%s|%d", inv, inv, inv, inv, inv)
	if strings.Contains(out, canary) {
		t.Error("canary in formatted Invocation")
	}
	// Corrupt value at the render layer: error must not echo it.
	bad := Validated{vals: map[string]string{"HOST": canary + "\x00"}, order: []string{"HOST"}}
	_, err = Render(c, bad)
	if !errors.Is(err, ErrRender) || strings.Contains(err.Error(), canary) {
		t.Errorf("err = %v", err)
	}
}

func TestRenderFailsClosed(t *testing.T) {
	c := renderDef(t)
	if _, err := Render(nil, Validated{}); err == nil {
		t.Error("nil compiled")
	}
	c2 := renderDef(t)
	c2.def.Interpreter = "python"
	if _, err := Render(c2, Validated{}); err == nil {
		t.Error("unsupported interpreter")
	}
	undeclared := Validated{vals: map[string]string{"NOPE": "x"}, order: []string{"NOPE"}}
	if _, err := Render(c, undeclared); err == nil {
		t.Error("undeclared parameter")
	}
	var nilInv *Invocation
	if nilInv.String() == "" {
		t.Error("nil String")
	}
}
