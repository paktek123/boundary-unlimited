// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbook

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"
)

// ErrInvalid is wrapped by every validation failure.
var ErrInvalid = errors.New("runbook: invalid parameters")

// Validated holds checked parameter values. Its formatting verbs print
// parameter names only, never values; use Get or Env to read a value.
type Validated struct {
	vals  map[string]string
	order []string
}

// Names returns the parameter names present, in declaration order.
func (v Validated) Names() []string { return append([]string(nil), v.order...) }

// Get returns the value of a parameter.
func (v Validated) Get(name string) (string, bool) { s, ok := v.vals[name]; return s, ok }

// String implements fmt.Stringer and prints names only.
func (v Validated) String() string { return fmt.Sprintf("runbook.Validated{names:%v}", v.order) }

// GoString implements fmt.GoStringer and prints names only.
func (v Validated) GoString() string { return v.String() }

// Format implements fmt.Formatter so no verb can print values.
func (v Validated) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(v.String())) }

// Validate checks values against the compiled definition. Undeclared and
// missing required parameters are rejected; defaults fill absent optional
// ones. Errors and recovered panics name parameters but never include a value.
// Go maps cannot hold duplicate keys, so callers that parse a repeated
// parameter from user input must reject duplicates before calling (see
// ValidatePairs).
func (c *Compiled) Validate(values map[string]string) (res Validated, err error) {
	defer func() {
		if recover() != nil {
			res, err = Validated{}, fmt.Errorf("%w: internal error", ErrInvalid)
		}
	}()
	if c == nil {
		return Validated{}, fmt.Errorf("%w: no definition", ErrInvalid)
	}
	var unknown []string
	for k := range values {
		if _, ok := c.byName[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return Validated{}, fmt.Errorf("%w: undeclared parameter count %d", ErrInvalid, len(unknown))
	}
	out := Validated{vals: map[string]string{}}
	for i := range c.params {
		p := &c.params[i]
		v, ok := values[p.Name]
		if !ok {
			switch {
			case p.HasDefault:
				v = p.Default
			case p.Required:
				return Validated{}, fmt.Errorf("%w: missing required parameter %q", ErrInvalid, p.Name)
			default:
				continue
			}
		}
		if err := p.check(v); err != nil {
			return Validated{}, fmt.Errorf("%w: parameter %q: %s", ErrInvalid, p.Name, err.Error())
		}
		out.vals[p.Name] = v
		out.order = append(out.order, p.Name)
	}
	return out, nil
}

// Pair is one name/value as supplied by a caller that may repeat names.
type Pair struct{ Name, Value string }

// ValidatePairs rejects a repeated name, then validates like Validate.
func (c *Compiled) ValidatePairs(pairs []Pair) (Validated, error) {
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		if _, dup := m[p.Name]; dup {
			return Validated{}, fmt.Errorf("%w: duplicate parameter %q", ErrInvalid, p.Name)
		}
		m[p.Name] = p.Value
	}
	return c.Validate(m)
}

// check validates one value. Its error text never contains the value.
func (p *compiledParam) check(v string) error {
	if len(v) > p.maxLen { // length first, before any regex work
		return errors.New("too long")
	}
	if !utf8.ValidString(v) {
		return errors.New("not valid UTF-8")
	}
	if hasControl(v) {
		return errors.New("contains NUL or control characters")
	}
	switch p.Type {
	case TypeString:
		if !p.re.MatchString(v) {
			return errors.New("does not match the declared regex")
		}
	case TypeEnum:
		for _, a := range p.AllowedValues {
			if a == v {
				return nil
			}
		}
		return errors.New("not an allowed value")
	case TypeInt:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return errors.New("not an integer")
		}
		if n < *p.Min || n > *p.Max {
			return errors.New("out of range")
		}
	case TypeBool:
		if v != "true" && v != "false" {
			return errors.New("not a bool")
		}
	default:
		return errors.New("unknown type")
	}
	return nil
}
