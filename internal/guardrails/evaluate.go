// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package guardrails

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Verdict is the outcome of evaluating a command.
type Verdict string

// Verdicts. Block means the exec request is rejected and nothing is forwarded.
const (
	VerdictAllow  Verdict = "allow"
	VerdictBlock  Verdict = "block"
	VerdictReview Verdict = "review"
)

// Decision is the result of Evaluate. By design it carries only the verdict,
// the id of the deciding rule (empty when no rule decided, for example for
// malformed input or an allow-list miss) and the rule-set hash. It never holds
// the command, a fragment, an offset or a hash of the command.
type Decision struct {
	Verdict     Verdict
	RuleID      string
	RuleSetHash string
}

// matcher is one applicable rule, ready to match.
type matcher struct {
	id     string
	action Action
	match  func(string) bool
}

func newMatcher(r Rule) (matcher, error) {
	m := matcher{id: r.ID, action: r.Action}
	switch r.Match.Kind {
	case MatchPrefix:
		p := r.Match.Pattern
		m.match = func(s string) bool {
			if !strings.HasPrefix(s, p) {
				return false
			}
			rest := s[len(p):]
			if rest == "" {
				return true
			}
			c, _ := utf8.DecodeRuneInString(rest)
			return unicode.IsSpace(c)
		}
	case MatchRegexp:
		re, err := regexp.Compile(r.Match.Pattern)
		if err != nil {
			return m, invalid(r.ID, "regexp does not compile (RE2 syntax only)")
		}
		m.match = re.MatchString
	default:
		return m, invalid(r.ID, "unknown match kind")
	}
	return m, nil
}

func (c *Compiled) block(rule string) Decision {
	return Decision{Verdict: VerdictBlock, RuleID: rule, RuleSetHash: c.RuleSetHash()}
}

// Evaluate decides what happens to a command. The raw string and its
// normalised form are both matched: if either matches a deny rule the result
// is Block; require_review rules likewise yield Review; deny wins over review.
// Malformed or over-length input (see Normalise), a nil receiver and any
// internal error or panic yield Block. The recovered panic value is discarded
// so no command text can reach an error or log.
//
// Without an allow list, a command that matches no rule is allowed. After
// WithAllowList, it is allowed only if both forms match an allow pattern.
//
// Prefix rules match at the start of the whole command only; use a regexp
// rule (for example with (?m)) to match later lines. Guardrails are a policy
// tripwire, not a sandbox (docs/rfc/guardrails.md).
func (c *Compiled) Evaluate(raw []byte) (d Decision) {
	if c == nil {
		return Decision{Verdict: VerdictBlock}
	}
	defer func() {
		if recover() != nil {
			d = c.block("")
		}
	}()
	norm, err := Normalise(raw, MaxCommandLen)
	if err != nil {
		return c.block("")
	}
	rawStr := string(raw)

	var review string
	for _, m := range c.matchers {
		if !m.match(rawStr) && !m.match(norm) {
			continue
		}
		switch m.action {
		case ActionDeny:
			return c.block(m.id)
		case ActionRequireReview:
			if review == "" {
				review = m.id
			}
		default:
			return c.block(m.id) // unknown action: fail closed
		}
	}
	if review != "" {
		return Decision{Verdict: VerdictReview, RuleID: review, RuleSetHash: c.hash}
	}
	if c.defaultDeny && (!anyMatch(c.allow, rawStr) || !anyMatch(c.allow, norm)) {
		return c.block("")
	}
	return Decision{Verdict: VerdictAllow, RuleSetHash: c.hash}
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// WithAllowList returns a copy of the rule set in default-deny mode: a command
// is allowed only if its raw and normalised forms each match at least one of
// the RE2 patterns and no deny or require_review rule matches. An empty list
// blocks every command. Patterns are validated under the same limits as rule
// patterns (count, length, UTF-8, must compile, must not match the empty
// string); any failure returns an error and no result. The rule-set hash
// covers the patterns.
func (c *Compiled) WithAllowList(patterns []string) (*Compiled, error) {
	if c == nil {
		return nil, ErrInvalidRule
	}
	if len(patterns) > c.limits.MaxRules {
		return nil, ErrTooManyRules
	}
	res := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if p == "" || len(p) > c.limits.MaxPatternLen || !utf8.ValidString(p) {
			return nil, fmt.Errorf("%w: allow pattern is empty, too long or not valid UTF-8", ErrInvalidRule)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			// Deliberately not wrapped: the parser echoes the pattern.
			return nil, fmt.Errorf("%w: allow pattern does not compile (RE2 syntax only)", ErrInvalidRule)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("%w: allow pattern matches the empty string", ErrInvalidRule)
		}
		res = append(res, re)
	}
	n := *c
	n.ruleIDs = append([]string(nil), c.ruleIDs...)
	n.matchers = append([]matcher(nil), c.matchers...)
	n.defaultDeny = true
	n.allow = res
	n.hash = allowListHash(c.hash, patterns)
	return &n, nil
}

func allowListHash(base string, patterns []string) string {
	ps := append([]string(nil), patterns...)
	sort.Strings(ps)
	h := sha256.New()
	str := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	str("guardrails-allowlist-v1")
	str(base)
	str(fmt.Sprint(len(ps)))
	for _, p := range ps {
		str(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}
