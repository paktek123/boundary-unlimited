// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package runbook

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// DefaultMaxLength is the per-value byte limit when a parameter sets none.
	DefaultMaxLength = 4 << 10
	// HardMaxLength is the compile-time maximum a parameter may raise its limit to.
	HardMaxLength = 64 << 10
	// MaxParameters bounds the number of parameters in one definition.
	MaxParameters = 64
	// MaxScriptBytes bounds the script body.
	MaxScriptBytes = 1 << 20
	// MaxNameLen bounds names so error messages stay small.
	MaxNameLen = 64
	// MaxRegexLen bounds a parameter regex source.
	MaxRegexLen = 1024
	// MaxEnumValues bounds the allowed-value list of an enum.
	MaxEnumValues = 256
)

// InterpreterPosixSh is the only interpreter supported in the first release;
// it receives parameters as environment variables / argv.
const InterpreterPosixSh = "sh"

var supportedInterpreters = map[string]struct{}{InterpreterPosixSh: {}}

var paramNameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// reservedNames is the single list of variable names a parameter may not use,
// because they change interpreter or loader behaviour.
var reservedNames = map[string]struct{}{
	"PATH": {}, "LD_PRELOAD": {}, "LD_LIBRARY_PATH": {}, "LD_AUDIT": {}, "IFS": {},
	"BASH_ENV": {}, "ENV": {}, "SHELLOPTS": {}, "BASHOPTS": {}, "PS1": {}, "PS4": {},
	"PROMPT_COMMAND": {}, "CDPATH": {}, "GLOBIGNORE": {}, "PYTHONPATH": {},
	"PYTHONSTARTUP": {}, "PERL5LIB": {}, "PERL5OPT": {}, "RUBYLIB": {}, "RUBYOPT": {},
	"NODE_OPTIONS": {}, "PS2": {}, "PS3": {}, "MAIL": {}, "MAILPATH": {}, "FPATH": {},
	"GCONV_PATH": {}, "LOCPATH": {}, "NLSPATH": {}, "TZ": {}, "HISTFILE": {}, "HOME": {}, "SHELL": {}, "USER": {}, "LOGNAME": {},
	"TMPDIR": {}, "LANG": {}, "TERM": {}, "PWD": {}, "OLDPWD": {},
}

// IsReservedName reports whether name may not be used as a parameter name.
// Names starting with LD_, BASH_, DYLD_, GCONV_, MALLOC_ or NODE_ are reserved as well.
func IsReservedName(name string) bool {
	if _, ok := reservedNames[name]; ok {
		return true
	}
	for _, p := range []string{"LD_", "BASH_", "DYLD_", "GCONV_", "MALLOC_", "NODE_"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Compiled is a validated Definition ready to validate run-time values.
type Compiled struct {
	def    Definition
	params []compiledParam
	byName map[string]int
}

type compiledParam struct {
	Parameter
	re     *regexp.Regexp // anchored; nil unless TypeString
	maxLen int
}

// Name returns the runbook name.
func (c *Compiled) Name() string { return c.def.Name }

// Selector returns a copy of the target selector.
func (c *Compiled) Selector() TargetSelector {
	s := c.def.Selector
	s.TargetIDs = append([]string(nil), s.TargetIDs...)
	s.ScopeIDs = append([]string(nil), s.ScopeIDs...)
	return s
}

// ParamNames returns the declared parameter names in declaration order.
func (c *Compiled) ParamNames() []string {
	out := make([]string, len(c.params))
	for i := range c.params {
		out[i] = c.params[i].Name
	}
	return out
}

// Option configures Compile. None exist yet; the type reserves the signature.
type Option func(*options)

type options struct{}

// Compile validates def and returns a Compiled definition. It fails closed:
// any problem rejects the whole definition. Errors name the parameter, never
// a value.
func Compile(def Definition, _ ...Option) (c *Compiled, err error) {
	defer func() {
		if recover() != nil {
			c, err = nil, errors.New("runbook: internal error compiling definition")
		}
	}()
	if def.Name == "" || len(def.Name) > MaxNameLen || !printable(def.Name) {
		return nil, errors.New("runbook: invalid name")
	}
	if len(def.Description) > 4096 || !utf8.ValidString(def.Description) {
		return nil, errors.New("runbook: invalid description")
	}
	if _, ok := supportedInterpreters[def.Interpreter]; !ok {
		return nil, errors.New("runbook: unsupported interpreter")
	}
	if len(def.Script) == 0 || len(def.Script) > MaxScriptBytes {
		return nil, errors.New("runbook: script empty or too large")
	}
	if len(def.Parameters) > MaxParameters {
		return nil, errors.New("runbook: too many parameters")
	}
	out := &Compiled{def: cloneDef(def), byName: map[string]int{}}
	for i, p := range out.def.Parameters {
		cp, err := compileParam(p)
		if err != nil {
			return nil, err
		}
		if _, dup := out.byName[p.Name]; dup {
			return nil, fmt.Errorf("runbook: duplicate parameter %q", p.Name)
		}
		out.byName[p.Name] = i
		out.params = append(out.params, cp)
	}
	// A default must pass the same validation as a supplied value.
	for i := range out.params {
		p := &out.params[i]
		if p.HasDefault {
			if err := p.check(p.Default); err != nil {
				return nil, fmt.Errorf("runbook: default of parameter %q is invalid: %w", p.Name, err)
			}
		}
	}
	return out, nil
}

func compileParam(p Parameter) (compiledParam, error) {
	cp := compiledParam{Parameter: p}
	if !paramNameRE.MatchString(p.Name) || len(p.Name) > MaxNameLen {
		return cp, errors.New("runbook: invalid parameter name (must match ^[A-Z][A-Z0-9_]*$)")
	}
	if IsReservedName(p.Name) {
		return cp, fmt.Errorf("runbook: parameter name %q is reserved", p.Name)
	}
	cp.maxLen = p.MaxLength
	if cp.maxLen == 0 {
		cp.maxLen = DefaultMaxLength
	}
	if cp.maxLen < 0 || cp.maxLen > HardMaxLength {
		return cp, fmt.Errorf("runbook: parameter %q max_length out of range", p.Name)
	}
	if !p.HasDefault && p.Default != "" {
		return cp, fmt.Errorf("runbook: parameter %q sets a default without has_default", p.Name)
	}
	switch p.Type {
	case TypeString:
		if p.Regex == "" || len(p.Regex) > MaxRegexLen {
			return cp, fmt.Errorf("runbook: string parameter %q needs a regex of at most %d bytes", p.Name, MaxRegexLen)
		}
		// Compile the author's regex on its own first: spliced into the
		// anchored form, an unbalanced ")" such as `x)|(.*` would otherwise
		// compile and escape the implicit anchoring.
		if _, err := regexp.Compile(p.Regex); err != nil {
			return cp, fmt.Errorf("runbook: parameter %q has an invalid RE2 regex", p.Name)
		}
		re, err := regexp.Compile(`\A(?:` + p.Regex + `)\z`)
		if err != nil {
			return cp, fmt.Errorf("runbook: parameter %q has an invalid RE2 regex", p.Name)
		}
		cp.re = re
	case TypeEnum:
		if len(p.AllowedValues) == 0 || len(p.AllowedValues) > MaxEnumValues {
			return cp, fmt.Errorf("runbook: enum parameter %q needs 1..%d allowed values", p.Name, MaxEnumValues)
		}
		seen := map[string]struct{}{}
		for _, v := range p.AllowedValues {
			if v == "" || len(v) > cp.maxLen || hasControl(v) {
				return cp, fmt.Errorf("runbook: enum parameter %q has an invalid allowed value", p.Name)
			}
			if _, ok := seen[v]; ok {
				return cp, fmt.Errorf("runbook: enum parameter %q has duplicate allowed values", p.Name)
			}
			seen[v] = struct{}{}
		}
	case TypeInt:
		if p.Min == nil || p.Max == nil || *p.Min > *p.Max {
			return cp, fmt.Errorf("runbook: int parameter %q needs min <= max", p.Name)
		}
	case TypeBool:
	default:
		return cp, fmt.Errorf("runbook: parameter %q has an unknown type", p.Name)
	}
	if p.Type != TypeString && p.Regex != "" {
		return cp, fmt.Errorf("runbook: parameter %q: regex only applies to string parameters", p.Name)
	}
	if p.Type != TypeEnum && len(p.AllowedValues) != 0 {
		return cp, fmt.Errorf("runbook: parameter %q: allowed_values only applies to enum parameters", p.Name)
	}
	if p.Type != TypeInt && (p.Min != nil || p.Max != nil) {
		return cp, fmt.Errorf("runbook: parameter %q: min/max only apply to int parameters", p.Name)
	}
	return cp, nil
}

func cloneDef(d Definition) Definition {
	d.Script = append([]byte(nil), d.Script...)
	d.Selector.TargetIDs = append([]string(nil), d.Selector.TargetIDs...)
	d.Selector.ScopeIDs = append([]string(nil), d.Selector.ScopeIDs...)
	ps := make([]Parameter, len(d.Parameters))
	for i, p := range d.Parameters {
		p.AllowedValues = append([]string(nil), p.AllowedValues...)
		if p.Min != nil {
			v := *p.Min
			p.Min = &v
		}
		if p.Max != nil {
			v := *p.Max
			p.Max = &v
		}
		ps[i] = p
	}
	d.Parameters = ps
	sort.Strings(d.Selector.TargetIDs)
	sort.Strings(d.Selector.ScopeIDs)
	return d
}

func printable(s string) bool { return utf8.ValidString(s) && !hasControl(s) }

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return true
		}
	}
	return false
}
