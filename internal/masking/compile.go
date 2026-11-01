// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package masking

import (
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Compiled is an immutable, validated rule set for one session. It is not
// wired into the controller or worker: it enables nothing by itself.
type Compiled struct {
	detectors []Detector
	maxLen    int
	ruleIDs   []string
}

// RuleIDs returns the ids of the rules that were compiled, in input order.
func (c *Compiled) RuleIDs() []string { return append([]string(nil), c.ruleIDs...) }

// Len returns the number of compiled rules. Zero means no masking applies.
func (c *Compiled) Len() int { return len(c.detectors) }

// NewRedactor returns a Redactor over w using the compiled rules.
func (c *Compiled) NewRedactor(w io.Writer) (*Redactor, error) {
	// "{detector}" makes each rule's own replacement text the output.
	return New(w,
		WithDetectors(append([]Detector{}, c.detectors...)...),
		WithMaxPatternLen(c.maxLen),
		WithReplacement("{detector}"))
}

// ruleDetector wraps a detector so that its Name is the rule's literal
// replacement text, which the Redactor substitutes for the match.
type ruleDetector struct {
	Detector
	text string
}

func (d ruleDetector) Name() string { return d.text }

// Partial forwards to the wrapped detector if it can hold back a partial match.
func (d ruleDetector) Partial(b []byte) int {
	if p, ok := d.Detector.(partialDetector); ok {
		return p.Partial(b)
	}
	return -1
}

func invalid(id, why string) error {
	return fmt.Errorf("%w: %q: %s", ErrInvalidRule, id, why)
}

// Compile selects the enabled rules that apply to the session and builds the
// detectors for them. It fails closed: any applicable rule that is invalid, a
// duplicate id, or too many applicable rules return an error and no result.
// Disabled rules and rules that do not apply to the session are ignored.
// Overlapping matches are merged to the widest span by the Redactor.
func Compile(rules []Rule, session SessionInfo, limits Limits) (*Compiled, error) {
	if limits.MaxRules < 0 || limits.MaxRegexLen < 0 || limits.MaxPatternLen < 0 || limits.MaxReplaceLen < 0 {
		return nil, ErrInvalidLimits
	}
	def := DefaultLimits()
	if limits.MaxRules == 0 {
		limits.MaxRules = def.MaxRules
	}
	if limits.MaxRegexLen == 0 {
		limits.MaxRegexLen = def.MaxRegexLen
	}
	if limits.MaxPatternLen == 0 {
		limits.MaxPatternLen = def.MaxPatternLen
	}
	if limits.MaxReplaceLen == 0 {
		limits.MaxReplaceLen = def.MaxReplaceLen
	}

	seen := make(map[string]struct{}, len(rules))
	c := &Compiled{detectors: []Detector{}, maxLen: limits.MaxPatternLen}
	for _, r := range rules {
		if r.ID == "" {
			return nil, invalid("", "rule id is required")
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateRuleID, r.ID)
		}
		seen[r.ID] = struct{}{}
		if !r.Enabled || !r.AppliesTo.matches(session) {
			continue
		}
		if len(c.detectors) >= limits.MaxRules {
			return nil, ErrTooManyRules
		}
		d, err := buildDetector(r, limits)
		if err != nil {
			return nil, err
		}
		c.detectors = append(c.detectors, d)
		c.ruleIDs = append(c.ruleIDs, r.ID)
	}
	return c, nil
}

func buildDetector(r Rule, l Limits) (Detector, error) {
	var d Detector
	switch r.Detector {
	case KindCreditCard:
		d = CardDetector()
	case KindEmail:
		d = EmailDetector()
	case KindAWSAccessKey:
		d = AWSAccessKeyDetector()
	case KindJWT:
		d = JWTDetector()
	case KindPrivateKey:
		d = PrivateKeyDetector()
	case KindRegex:
		if r.Regex == "" {
			return nil, invalid(r.ID, "regex is required")
		}
		if len(r.Regex) > l.MaxRegexLen {
			return nil, invalid(r.ID, "regex exceeds the length limit")
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			// Deliberately not wrapped: the parser echoes the pattern.
			return nil, invalid(r.ID, "regex does not compile (RE2 syntax only)")
		}
		if re.Match(nil) {
			return nil, invalid(r.ID, "regex matches the empty string")
		}
		d = &RegexDetector{name: string(KindRegex), re: re}
	default:
		return nil, invalid(r.ID, "unknown detector")
	}
	if r.Detector != KindRegex && r.Regex != "" {
		return nil, invalid(r.ID, "regex is only allowed for the regex detector")
	}
	text := r.Replacement
	if text == "" {
		text = "[REDACTED:" + string(r.Detector) + "]"
	} else if err := checkReplacement(text, l.MaxReplaceLen); err != nil {
		return nil, invalid(r.ID, err.Error())
	}
	return ruleDetector{Detector: d, text: text}, nil
}

// checkReplacement rejects placeholders and back-references so that a
// replacement can never echo the matched text.
func checkReplacement(s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("replacement exceeds the length limit")
	}
	if strings.ContainsAny(s, "${}\\") {
		return fmt.Errorf("replacement must be literal text (no placeholders or back-references)")
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("replacement contains control characters")
		}
	}
	return nil
}
