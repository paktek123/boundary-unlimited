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
	"unicode/utf8"
)

// Compiled is an immutable, validated rule set for one session. It is not
// wired into the controller or worker: it enables nothing by itself.
type Compiled struct {
	ruleIDs []string
	hash    string
}

// RuleIDs returns the ids of the applicable rules, in input order. It is safe
// to call on a nil receiver.
func (c *Compiled) RuleIDs() []string {
	if c == nil {
		return nil
	}
	return append([]string(nil), c.ruleIDs...)
}

// Len returns the number of applicable rules. Zero means no guardrail applies.
func (c *Compiled) Len() int {
	if c == nil {
		return 0
	}
	return len(c.ruleIDs)
}

// RuleSetHash returns the hex SHA-256 over the canonical form of the
// applicable rules; it does not depend on input order.
func (c *Compiled) RuleSetHash() string {
	if c == nil {
		return ""
	}
	return c.hash
}

func invalid(id, why string) error {
	return fmt.Errorf("%w: %q: %s", ErrInvalidRule, id, why)
}

func resolveLimits(l Limits) (Limits, error) {
	if l.MaxRules < 0 || l.MaxPatternLen < 0 || l.MaxMessageLen < 0 {
		return l, ErrInvalidLimits
	}
	if l.MaxRules == 0 {
		l.MaxRules = DefaultMaxRules
	}
	if l.MaxPatternLen == 0 {
		l.MaxPatternLen = DefaultMaxPatternLen
	}
	if l.MaxMessageLen == 0 {
		l.MaxMessageLen = DefaultMaxMessageLen
	}
	if l.MaxRules > HardMaxRules || l.MaxPatternLen > HardMaxPatternLen || l.MaxMessageLen > HardMaxMessageLen {
		return l, ErrInvalidLimits
	}
	return l, nil
}

// Compile validates the rules and selects the enabled ones that apply to the
// session. It fails closed: any invalid enabled rule (applicable or not), a
// duplicate or empty id, a require_review rule that applies when reviews are
// unsupported, or more applicable rules than the limit returns an error and
// no result. Disabled rules are only checked for a usable, unique id.
func Compile(rules []Rule, session SessionInfo, limits Limits) (*Compiled, error) {
	limits, err := resolveLimits(limits)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(rules))
	var applied []Rule
	for _, r := range rules {
		if r.ID == "" {
			return nil, invalid("", "rule id is required")
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateRuleID, r.ID)
		}
		seen[r.ID] = struct{}{}
		if !r.Enabled {
			continue
		}
		if err := validate(r, limits); err != nil {
			return nil, err
		}
		if !r.Selectors.matches(session) {
			continue
		}
		if r.Action == ActionRequireReview && !limits.ReviewsSupported {
			return nil, invalid(r.ID, "require_review is not supported")
		}
		if len(applied) >= limits.MaxRules {
			return nil, ErrTooManyRules
		}
		applied = append(applied, r)
	}
	c := &Compiled{ruleIDs: make([]string, 0, len(applied))}
	for _, r := range applied {
		c.ruleIDs = append(c.ruleIDs, r.ID)
	}
	c.hash = ruleSetHash(applied)
	return c, nil
}

func validate(r Rule, l Limits) error {
	switch r.Action {
	case ActionDeny, ActionRequireReview:
	default:
		return invalid(r.ID, "unknown action")
	}
	p := r.Match.Pattern
	if p == "" {
		return invalid(r.ID, "pattern is required")
	}
	if len(p) > l.MaxPatternLen {
		return invalid(r.ID, "pattern exceeds the length limit")
	}
	if !utf8.ValidString(p) {
		return invalid(r.ID, "pattern is not valid UTF-8")
	}
	switch r.Match.Kind {
	case MatchPrefix:
		if strings.TrimSpace(p) == "" {
			return invalid(r.ID, "prefix is blank")
		}
	case MatchRegexp:
		re, err := regexp.Compile(p)
		if err != nil {
			// Deliberately not wrapped: the parser echoes the pattern.
			return invalid(r.ID, "regexp does not compile (RE2 syntax only)")
		}
		if re.MatchString("") {
			return invalid(r.ID, "regexp matches the empty string")
		}
	default:
		return invalid(r.ID, "unknown match kind")
	}
	if len(r.Message) > l.MaxMessageLen {
		return invalid(r.ID, "message exceeds the length limit")
	}
	if !utf8.ValidString(r.Message) {
		return invalid(r.ID, "message is not valid UTF-8")
	}
	if strings.ContainsAny(r.Message, "${}\\") {
		return invalid(r.ID, "message must be literal text (no placeholders)")
	}
	for _, c := range r.Message {
		if c < 0x20 || c == 0x7f {
			return invalid(r.ID, "message contains control characters")
		}
	}
	return nil
}

// ruleSetHash hashes the canonical form of the applicable rules, sorted by id,
// with length-prefixed fields and sorted selector lists.
func ruleSetHash(applied []Rule) string {
	sel := append([]Rule(nil), applied...)
	sort.Slice(sel, func(i, j int) bool { return sel[i].ID < sel[j].ID })

	h := sha256.New()
	str := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	list := func(in []string) {
		in = append([]string(nil), in...)
		sort.Strings(in)
		str(fmt.Sprint(len(in)))
		for _, s := range in {
			str(s)
		}
	}
	str("guardrails-ruleset-v1")
	str(fmt.Sprint(len(sel)))
	for _, r := range sel {
		str(r.ID)
		str(r.ScopeID)
		str(string(r.Match.Kind))
		str(r.Match.Pattern)
		str(string(r.Action))
		str(r.Message)
		str(fmt.Sprint(r.Selectors.AllTargets))
		list(r.Selectors.TargetIDs)
		list(r.Selectors.ScopeIDs)
		list(r.Selectors.RoleIDs)
		list(r.Selectors.PrincipalIDs)
	}
	return hex.EncodeToString(h.Sum(nil))
}
