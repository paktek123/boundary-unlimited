// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package runbook

import (
	"errors"
	"fmt"
)

// EnvPrefix namespaces every parameter in the environment of a run, so a
// parameter can never replace PATH, LD_PRELOAD, IFS or any other variable the
// shell or loader reads. The script reads parameter NAME as $RB_NAME.
const EnvPrefix = "RB_"

// ErrRender is wrapped by every render failure. Messages never carry values.
var ErrRender = errors.New("runbook: cannot render invocation")

// Invocation is what a worker would execute. Script is exactly the pinned
// script bytes, never modified. Parameter values appear ONLY in Env (as
// RB_<NAME>=<value>); Args is fixed and never carries a value in v1. Its
// formatting verbs print names only.
type Invocation struct {
	Script []byte
	Env    []string
	Args   []string
	names  []string
}

// String implements fmt.Stringer; names only, never values or script text.
func (i *Invocation) String() string {
	if i == nil {
		return "runbook.Invocation{nil}"
	}
	return fmt.Sprintf("runbook.Invocation{params:%v, script_bytes:%d}", i.names, len(i.Script))
}

// GoString implements fmt.GoStringer.
func (i *Invocation) GoString() string { return i.String() }

// Format implements fmt.Formatter so no verb can print values.
func (i *Invocation) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(i.String())) }

// Render builds the invocation for a validated run. It performs no text
// substitution: the script is copied byte for byte and each value is passed
// as a namespaced environment variable. Only the POSIX shell interpreter is
// supported. It fails closed.
func Render(c *Compiled, v Validated) (inv *Invocation, err error) {
	defer func() {
		if recover() != nil {
			inv, err = nil, fmt.Errorf("%w: internal error", ErrRender)
		}
	}()
	if c == nil {
		return nil, fmt.Errorf("%w: no definition", ErrRender)
	}
	if c.def.Interpreter != InterpreterPosixSh {
		return nil, fmt.Errorf("%w: unsupported interpreter", ErrRender)
	}
	out := &Invocation{
		Script: append([]byte(nil), c.def.Script...),
		Args:   []string{},
	}
	for _, name := range v.Names() {
		if _, ok := c.byName[name]; !ok {
			return nil, fmt.Errorf("%w: undeclared parameter %q", ErrRender, name)
		}
		val, _ := v.Get(name)
		// Defence in depth: validation already did this.
		if !printable(val) {
			return nil, fmt.Errorf("%w: parameter %q has invalid characters", ErrRender, name)
		}
		out.Env = append(out.Env, EnvPrefix+name+"="+val)
		out.names = append(out.names, name)
	}
	return out, nil
}
