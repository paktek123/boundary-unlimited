// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package guardrails

import "errors"

// MatchKind says how a Rule's pattern is matched against command text.
type MatchKind string

// Match kinds.
const (
	// MatchPrefix matches when the command starts with the pattern and the
	// pattern ends at a word boundary (end of command or whitespace follows).
	MatchPrefix MatchKind = "prefix"
	// MatchRegexp matches an RE2 regular expression (stdlib regexp only).
	MatchRegexp MatchKind = "regexp"
)

// Action is what happens to a command that matches a rule. There is no allow
// action: guardrails only restrict.
type Action string

// Actions.
const (
	ActionDeny          Action = "deny"
	ActionRequireReview Action = "require_review"
)

// Match is a rule's pattern.
type Match struct {
	Kind    MatchKind
	Pattern string
}

// Selectors say which sessions a Rule applies to. The zero value matches
// nothing: a rule applies to everything only if AllTargets is set explicitly.
type Selectors struct {
	AllTargets   bool
	TargetIDs    []string
	ScopeIDs     []string // matched against the session's scope and its ancestors
	RoleIDs      []string
	PrincipalIDs []string
}

// Rule is one guardrail rule.
type Rule struct {
	ID          string
	Name        string
	Description string
	ScopeID     string
	Match       Match
	Action      Action
	Selectors   Selectors
	// Message is literal text shown to the user when the rule blocks a
	// command. It must not use placeholders, so it can never echo the command.
	Message string
	Enabled bool
}

// SessionInfo describes the session the rules are compiled for.
type SessionInfo struct {
	TargetID     string
	ScopeIDs     []string // the target's scope and all its ancestor scopes
	RoleIDs      []string
	PrincipalIDs []string
}

// Limits bound the cost of a compiled rule set. A zero numeric field selects
// the default; a negative field, or a field above its hard maximum, is an
// error.
type Limits struct {
	MaxRules      int // applicable enabled rules per session
	MaxPatternLen int // bytes per match pattern
	MaxMessageLen int // bytes per message
	// ReviewsSupported must be set by a caller that can actually enforce
	// require_review. The zero value rejects applicable require_review rules.
	ReviewsSupported bool
}

// Defaults and hard maxima. Configuration cannot exceed the maxima.
const (
	DefaultMaxRules      = 64
	DefaultMaxPatternLen = 512
	DefaultMaxMessageLen = 256

	HardMaxRules      = 256
	HardMaxPatternLen = 4096
	HardMaxMessageLen = 1024
)

// DefaultLimits returns the default Limits (reviews unsupported).
func DefaultLimits() Limits {
	return Limits{
		MaxRules:      DefaultMaxRules,
		MaxPatternLen: DefaultMaxPatternLen,
		MaxMessageLen: DefaultMaxMessageLen,
	}
}

// Errors returned by Compile. Messages carry the rule id but never a pattern.
var (
	ErrInvalidRule     = errors.New("guardrails: invalid rule")
	ErrTooManyRules    = errors.New("guardrails: too many applicable rules")
	ErrInvalidLimits   = errors.New("guardrails: invalid limits")
	ErrDuplicateRuleID = errors.New("guardrails: duplicate rule id")
)

func intersects(a, b []string) bool {
	for _, x := range a {
		if x == "" {
			continue
		}
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// matches reports whether the selectors apply to the session. Empty
// selectors match nothing.
func (s Selectors) matches(si SessionInfo) bool {
	if s.AllTargets {
		return true
	}
	if si.TargetID != "" {
		for _, t := range s.TargetIDs {
			if t == si.TargetID {
				return true
			}
		}
	}
	return intersects(s.ScopeIDs, si.ScopeIDs) ||
		intersects(s.RoleIDs, si.RoleIDs) ||
		intersects(s.PrincipalIDs, si.PrincipalIDs)
}
