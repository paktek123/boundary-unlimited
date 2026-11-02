// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package masking

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Origin says where a rule was defined relative to the target being
// protected. The zero value is OriginParent so that an unset origin gets the
// strongest protection (fail closed).
type Origin int

// Rule origins.
const (
	// OriginParent: the rule is owned by a parent scope of the target's scope.
	// Child scopes cannot disable, replace or narrow it.
	OriginParent Origin = iota
	// OriginChild: the rule was added by the target's own (child) scope.
	OriginChild
)

// PolicyRule is a Rule together with its origin.
type PolicyRule struct {
	Rule   Rule
	Origin Origin
}

// BuiltinRulePrefix is reserved for the rules the policy adds itself.
const BuiltinRulePrefix = "builtin:"

// Errors returned by EffectivePolicy.
var (
	// ErrEmptyPolicy is returned when no rule applies and a no-op policy was
	// not explicitly allowed.
	ErrEmptyPolicy = errors.New("masking: no rules apply and a no-op policy was not explicitly allowed")
	// ErrReservedRuleID is returned for a custom rule using the built-in prefix.
	ErrReservedRuleID = errors.New("masking: rule id uses the reserved built-in prefix")
	// ErrParentRuleOverride is returned when a child-origin rule reuses the id
	// of a parent-origin rule (an attempt to replace or narrow it).
	ErrParentRuleOverride = errors.New("masking: a child scope cannot override a parent-scope rule")
)

// PolicyInput is the input of EffectivePolicy.
type PolicyInput struct {
	// RecordingEnabled is true when the target has session recording enabled.
	// The mandatory built-in detectors then always apply.
	RecordingEnabled bool
	// IncludeEmail adds the (optional, low sensitivity) email built-in when
	// RecordingEnabled is true.
	IncludeEmail bool
	// AllowNoop explicitly permits a policy with no applicable rule. It has no
	// effect when RecordingEnabled is true (built-ins always apply).
	AllowNoop bool
	Rules     []PolicyRule
	// ChildDisabled lists rule ids a child scope asked to disable. It is only
	// honoured for child-origin rules; entries naming parent-origin rules or
	// built-ins are ignored (and counted by IgnoredOverrides); entries naming
	// no rule are ignored silently and not counted.
	ChildDisabled []string
	Session       SessionInfo
	Limits        Limits
}

// Policy is the effective, compiled masking configuration for one session.
type Policy struct {
	compiled *Compiled
	hash     string
	ignored  int
}

// RuleSetHash returns the hex SHA-256 over the canonical form of the rules
// that apply to the session, for the recording record.
func (p *Policy) RuleSetHash() string { return p.hash }

// RuleIDs returns the ids of the effective rules in compile order.
func (p *Policy) RuleIDs() []string { return p.compiled.RuleIDs() }

// Len returns the number of effective rules. Zero is only possible when a
// no-op policy was explicitly allowed.
func (p *Policy) Len() int { return p.compiled.Len() }

// IgnoredOverrides returns how many child attempts to disable a parent-origin
// rule or a built-in were ignored.
func (p *Policy) IgnoredOverrides() int { return p.ignored }

// NewRedactor returns a Redactor over w using the effective rules.
func (p *Policy) NewRedactor(w io.Writer) (*Redactor, error) {
	return p.compiled.NewRedactor(w)
}

func builtinRules(email bool) []Rule {
	kinds := []DetectorKind{KindCreditCard, KindAWSAccessKey, KindJWT, KindPrivateKey}
	if email {
		kinds = append(kinds, KindEmail)
	}
	out := make([]Rule, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, Rule{
			ID:        BuiltinRulePrefix + string(k),
			Detector:  k,
			AppliesTo: Selectors{AllTargets: true},
			Enabled:   true,
		})
	}
	return out
}

// EffectivePolicy computes the rules that actually apply to a session. It
// fails closed: on any error it returns no policy, and it never returns an
// empty (pass-through) policy unless in.AllowNoop is set and recording is off.
//
//   - With RecordingEnabled, the built-in detectors credit_card, aws_access_key,
//     jwt and private_key (and email if IncludeEmail) are always included and
//     cannot be removed or disabled by any rule or flag.
//   - Parent-origin rules keep the owner's Enabled value; a child's disable
//     request is ignored for them, and a child-origin rule that reuses a
//     parent-origin rule id is rejected.
//   - Not wired into the controller or worker: nothing is enabled by this.
func EffectivePolicy(in PolicyInput) (*Policy, error) {
	parentIDs := map[string]struct{}{}
	for _, pr := range in.Rules {
		if pr.Origin == OriginParent {
			parentIDs[pr.Rule.ID] = struct{}{}
		}
	}
	childDisabled := make(map[string]struct{}, len(in.ChildDisabled))
	for _, id := range in.ChildDisabled {
		childDisabled[id] = struct{}{}
	}

	var ignored int
	rules := make([]Rule, 0, len(in.Rules)+5)
	if in.RecordingEnabled {
		rules = append(rules, builtinRules(in.IncludeEmail)...)
	}
	for id := range childDisabled {
		if _, isParent := parentIDs[id]; isParent || strings.HasPrefix(id, BuiltinRulePrefix) {
			ignored++
		}
	}
	for _, pr := range in.Rules {
		r := pr.Rule
		if strings.HasPrefix(r.ID, BuiltinRulePrefix) {
			return nil, fmt.Errorf("%w: %q", ErrReservedRuleID, r.ID)
		}
		switch pr.Origin {
		case OriginParent:
		case OriginChild:
			if _, clash := parentIDs[r.ID]; clash {
				return nil, fmt.Errorf("%w: %q", ErrParentRuleOverride, r.ID)
			}
			if _, off := childDisabled[r.ID]; off {
				r.Enabled = false
			}
		default:
			return nil, fmt.Errorf("%w: %q: unknown origin", ErrInvalidRule, r.ID)
		}
		rules = append(rules, r)
	}

	c, err := Compile(rules, in.Session, in.Limits)
	if err != nil {
		return nil, err
	}
	if c.Len() == 0 && (!in.AllowNoop || in.RecordingEnabled) {
		return nil, ErrEmptyPolicy
	}
	if in.RecordingEnabled && c.Len() < len(builtinRules(false)) {
		// Defensive: the built-ins must have been compiled.
		return nil, ErrEmptyPolicy
	}
	return &Policy{compiled: c, hash: ruleSetHash(rules, in.Session, c), ignored: ignored}, nil
}

// ruleSetHash hashes the canonical form of the applicable enabled rules,
// sorted by id, with length-prefixed fields and sorted selector lists.
func ruleSetHash(rules []Rule, si SessionInfo, c *Compiled) string {
	applied := make(map[string]struct{}, c.Len())
	for _, id := range c.ruleIDs {
		applied[id] = struct{}{}
	}
	sel := make([]Rule, 0, len(applied))
	for _, r := range rules {
		if _, ok := applied[r.ID]; ok {
			sel = append(sel, r)
		}
	}
	sort.Slice(sel, func(i, j int) bool { return sel[i].ID < sel[j].ID })

	h := sha256.New()
	str := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	list := func(l []string) {
		l = append([]string(nil), l...)
		sort.Strings(l)
		str(fmt.Sprint(len(l)))
		for _, s := range l {
			str(s)
		}
	}
	str("masking-ruleset-v1")
	str(fmt.Sprint(c.maxLen))
	for _, r := range sel {
		str(r.ID)
		str(r.ScopeID)
		str(string(r.Detector))
		str(r.Regex)
		str(r.Replacement)
		str(fmt.Sprint(r.AppliesTo.AllTargets))
		list(r.AppliesTo.TargetIDs)
		list(r.AppliesTo.ScopeIDs)
		list(r.AppliesTo.RoleIDs)
		list(r.AppliesTo.PrincipalIDs)
	}
	return hex.EncodeToString(h.Sum(nil))
}
