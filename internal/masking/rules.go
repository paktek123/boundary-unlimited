// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package masking

import "errors"

// DetectorKind names the detector a Rule uses: one of the built-in kinds or
// KindRegex for a custom RE2 pattern.
type DetectorKind string

// Detector kinds.
const (
	KindCreditCard   DetectorKind = "credit_card"
	KindEmail        DetectorKind = "email"
	KindAWSAccessKey DetectorKind = "aws_access_key"
	KindJWT          DetectorKind = "jwt"
	KindPrivateKey   DetectorKind = "private_key"
	KindRegex        DetectorKind = "regex"
)

// Selectors say which sessions a Rule applies to. The zero value matches
// nothing: a rule applies to everything only if AllTargets is set explicitly.
type Selectors struct {
	AllTargets   bool
	TargetIDs    []string
	ScopeIDs     []string // matched against the session's scope and its ancestors
	RoleIDs      []string
	PrincipalIDs []string
}

// Rule is one masking rule (see docs/rfc/data-masking.md, "Rule model").
type Rule struct {
	ID          string
	Name        string
	Description string
	ScopeID     string
	Detector    DetectorKind
	// Regex is the RE2 pattern; required if and only if Detector is KindRegex.
	Regex string
	// Replacement is the literal text written instead of a match. Empty means
	// "[REDACTED:<detector kind>]". It must not use placeholders or
	// back-references.
	Replacement string
	AppliesTo   Selectors
	Enabled     bool
}

// SessionInfo describes the session the rules are compiled for.
type SessionInfo struct {
	TargetID     string
	ScopeIDs     []string // the target's scope and all its ancestor scopes
	RoleIDs      []string
	PrincipalIDs []string
}

// Limits bound the cost of a compiled rule set. A zero field selects the
// default; a negative field is an error.
type Limits struct {
	MaxRules      int // applicable enabled rules per session
	MaxRegexLen   int // bytes per custom pattern
	MaxPatternLen int // longest match and lookbehind, passed to the Redactor
	MaxReplaceLen int // bytes per replacement
}

// Default limits.
const (
	DefaultMaxRules      = 32
	DefaultMaxRegexLen   = 512
	DefaultMaxReplaceLen = 128
)

// DefaultLimits returns the default Limits.
func DefaultLimits() Limits {
	return Limits{
		MaxRules:      DefaultMaxRules,
		MaxRegexLen:   DefaultMaxRegexLen,
		MaxPatternLen: DefaultMaxPatternLen,
		MaxReplaceLen: DefaultMaxReplaceLen,
	}
}

// Errors returned by Compile. Messages carry the rule id but never a pattern.
var (
	ErrInvalidRule     = errors.New("masking: invalid rule")
	ErrTooManyRules    = errors.New("masking: too many applicable rules")
	ErrInvalidLimits   = errors.New("masking: invalid limits")
	ErrDuplicateRuleID = errors.New("masking: duplicate rule id")
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
