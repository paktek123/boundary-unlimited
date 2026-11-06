// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package runbook

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Lint is a TRIPWIRE, not a guarantee. It looks for well-known patterns that
// re-evaluate a parameter value as shell code. A script can defeat it (for
// example through here-documents, indirect expansion or an interpreter it
// does not know), so it never replaces binding-only delivery of values.

// Lint rule ids.
const (
	RuleEval           = "lint.eval"
	RuleShellC         = "lint.shell_c_param"
	RuleSourceParam    = "lint.source_param"
	RuleCommandSubst   = "lint.command_substitution_param"
	RuleUnquoted       = "lint.unquoted_expansion"
	RuleUntokenisable  = "lint.untokenisable"
	RuleTooManyFinding = "lint.too_many_findings"
)

// MaxLintFindings bounds the number of findings Lint returns.
const MaxLintFindings = 100

// Finding is one lint result. It carries the rule id, the 1-based line number
// and the parameter name (empty when no parameter is involved). It never
// carries a script excerpt.
type Finding struct {
	Rule  string
	Line  int
	Param string
}

var (
	evalRE   = regexp.MustCompile(`(^|[;&|(\s{])eval(\s|$)`)
	shellCRE = regexp.MustCompile(`(^|[;&|(\s{])(sh|bash|dash|ash|ksh|zsh)\s+(-[A-Za-z]*c|-[A-Za-z]+\s+-c)\b`)
	sourceRE = regexp.MustCompile(`(^|[;&|(\s{])(source|\.)\s+["']?\$`)
)

// Lint scans script for unsafe re-evaluation of the declared parameters. It
// fails closed: a script it cannot tokenise, or that is larger than
// MaxScriptBytes, yields an untokenisable finding. At most MaxLintFindings
// findings are returned.
func Lint(script []byte, paramNames []string) (out []Finding) {
	defer func() {
		if recover() != nil {
			out = []Finding{{Rule: RuleUntokenisable, Line: 1}}
		}
	}()
	if len(script) > MaxScriptBytes || !utf8.Valid(script) || strings.ContainsRune(string(script), 0) {
		return []Finding{{Rule: RuleUntokenisable, Line: 1}}
	}
	names := make(map[string]struct{}, len(paramNames))
	for _, n := range paramNames {
		names[n] = struct{}{}
	}
	add := func(f Finding) bool {
		if len(out) >= MaxLintFindings {
			return false
		}
		out = append(out, f)
		return true
	}
	src := string(script)
	var (
		line               = 1
		inSingle, inDouble bool
		code               strings.Builder // current line with comments removed
		codeLine           = 1
	)
	// lineParams records declared parameters expanded on the current line
	// (in any quote state) for the line-oriented rules.
	var lineParams []string
	flush := func() bool {
		text := code.String()
		code.Reset()
		params := lineParams
		lineParams = nil
		ln := codeLine
		codeLine = line
		if evalRE.MatchString(text) && !add(Finding{Rule: RuleEval, Line: ln}) {
			return false
		}
		if shellCRE.MatchString(text) {
			for _, p := range params {
				if !add(Finding{Rule: RuleShellC, Line: ln, Param: p}) {
					return false
				}
			}
		}
		if sourceRE.MatchString(text) {
			for _, p := range params {
				if !add(Finding{Rule: RuleSourceParam, Line: ln, Param: p}) {
					return false
				}
			}
		}
		return true
	}
	truncated := func() []Finding {
		if len(out) >= MaxLintFindings {
			out = append(out[:MaxLintFindings-1], Finding{Rule: RuleTooManyFinding, Line: line})
		}
		return out
	}
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			if !flush() {
				return truncated()
			}
			line++
			codeLine = line
			code.WriteByte(c)
			code.Reset()
			i++
		case c == '\\' && !inSingle:
			code.WriteByte(c)
			if i+1 < len(src) {
				if src[i+1] == '\n' {
					line++
				} else {
					code.WriteByte(src[i+1])
				}
			}
			i += 2
		case c == '#' && !inSingle && !inDouble && (i == 0 || strings.IndexByte(" \t\n;|&(", src[i-1]) >= 0):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			code.WriteByte(c)
			i++
		case c == '"' && !inSingle:
			inDouble = !inDouble
			code.WriteByte(c)
			i++
		case c == '`' && !inSingle:
			end := strings.IndexByte(src[i+1:], '`')
			if end < 0 {
				return []Finding{{Rule: RuleUntokenisable, Line: line}}
			}
			span := src[i+1 : i+1+end]
			for _, p := range expansionsIn(span, names) {
				if !add(Finding{Rule: RuleCommandSubst, Line: line, Param: p}) {
					return truncated()
				}
			}
			line += strings.Count(span, "\n")
			i += end + 2
		case c == '$' && !inSingle && i+1 < len(src) && src[i+1] == '(':
			end := matchParen(src, i+1)
			if end < 0 {
				return []Finding{{Rule: RuleUntokenisable, Line: line}}
			}
			span := src[i+2 : end]
			for _, p := range expansionsIn(span, names) {
				if !add(Finding{Rule: RuleCommandSubst, Line: line, Param: p}) {
					return truncated()
				}
			}
			line += strings.Count(span, "\n")
			i = end + 1
		case c == '$' && !inSingle:
			name, n := paramAt(src, i)
			if _, ok := names[name]; ok && name != "" {
				lineParams = append(lineParams, name)
				if !inDouble && !add(Finding{Rule: RuleUnquoted, Line: line, Param: name}) {
					return truncated()
				}
			}
			code.WriteString(src[i : i+max(n, 1)])
			i += max(n, 1)
		default:
			code.WriteByte(c)
			i++
		}
	}
	if inSingle || inDouble {
		return []Finding{{Rule: RuleUntokenisable, Line: line}}
	}
	if !flush() {
		return truncated()
	}
	return out
}

// paramAt parses $NAME or ${NAME...} at src[i] and returns the name and the
// number of bytes consumed. name is empty for other expansions ($1, $?, ...).
func paramAt(src string, i int) (string, int) {
	j := i + 1
	if j >= len(src) {
		return "", 1
	}
	braced := src[j] == '{'
	if braced {
		j++
	}
	k := j
	for k < len(src) && (src[k] == '_' || src[k] >= '0' && src[k] <= '9' || src[k] >= 'A' && src[k] <= 'Z' || src[k] >= 'a' && src[k] <= 'z') {
		k++
	}
	if k == j {
		return "", 1
	}
	name := src[j:k]
	if braced {
		if end := strings.IndexByte(src[k:], '}'); end >= 0 {
			return name, k + end + 1 - i
		}
		return name, k - i
	}
	return name, k - i
}

// expansionsIn returns the declared parameters expanded anywhere in span.
func expansionsIn(span string, names map[string]struct{}) []string {
	var out []string
	for i := 0; i < len(span); i++ {
		if span[i] != '$' {
			continue
		}
		name, n := paramAt(span, i)
		if _, ok := names[name]; ok && name != "" {
			out = append(out, name)
		}
		i += max(n, 1) - 1
	}
	return out
}

// matchParen returns the index of the ')' that closes the '(' at src[open],
// or -1.
func matchParen(src string, open int) int {
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
