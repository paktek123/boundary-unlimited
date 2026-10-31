// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package masking

import (
	"fmt"
	"regexp"
)

// Span is a half-open byte range [Start, End) of sensitive data.
type Span struct {
	Start, End int
}

// Detector finds sensitive data in a byte slice. Implementations must be safe
// for concurrent use and must not retain b.
type Detector interface {
	// Name is used in the replacement token.
	Name() string
	// Find returns the non-overlapping spans of sensitive data in b.
	Find(b []byte) []Span
}

// partialDetector is implemented by detectors whose matches can be large and
// have a recognisable start (for example a PEM block). Partial returns the
// offset of a construct that has started in b but is not yet complete, or -1.
// The redactor holds back everything from that offset.
type partialDetector interface {
	Partial(b []byte) int
}

// RegexDetector is a Detector backed by a Go regexp (RE2: linear time, no
// catastrophic backtracking). An optional validate func filters candidates.
type RegexDetector struct {
	name     string
	re       *regexp.Regexp
	validate func(match []byte) bool
}

// NewRegexDetector compiles a custom detector. Patterns that can match the
// empty string are rejected.
func NewRegexDetector(name, pattern string) (*RegexDetector, error) {
	if name == "" {
		return nil, fmt.Errorf("masking: detector name is required")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("masking: detector %q: %w", name, err)
	}
	if re.Match(nil) {
		return nil, fmt.Errorf("masking: detector %q: pattern matches the empty string", name)
	}
	return &RegexDetector{name: name, re: re}, nil
}

// Name implements Detector.
func (d *RegexDetector) Name() string { return d.name }

// Find implements Detector.
func (d *RegexDetector) Find(b []byte) []Span {
	var out []Span
	for _, loc := range d.re.FindAllIndex(b, -1) {
		if loc[1] == loc[0] {
			continue
		}
		if d.validate != nil && !d.validate(b[loc[0]:loc[1]]) {
			continue
		}
		out = append(out, Span{loc[0], loc[1]})
	}
	return out
}

var (
	cardRe   = regexp.MustCompile(`\b[0-9](?:[ -]?[0-9]){12,18}\b`)
	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){1,6}`)
	awsRe    = regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z2-7]{16}\b`)
	jwtRe    = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{4,}\.eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]*`)
	pemRe    = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	pemBegin = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
)

// luhnValid reports whether the digits in b (ignoring spaces and dashes) are
// 13 to 19 digits long and pass the Luhn check.
func luhnValid(b []byte) bool {
	var digits []int
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			digits = append(digits, int(c-'0'))
		case c == ' ' || c == '-':
		default:
			return false
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// CardDetector finds 13 to 19 digit payment card numbers (optionally
// separated by single spaces or dashes) that pass the Luhn check.
func CardDetector() Detector {
	return &RegexDetector{name: "credit_card", re: cardRe, validate: luhnValid}
}

// EmailDetector finds email addresses.
func EmailDetector() Detector { return &RegexDetector{name: "email", re: emailRe} }

// AWSAccessKeyDetector finds AWS access key ids.
func AWSAccessKeyDetector() Detector { return &RegexDetector{name: "aws_access_key", re: awsRe} }

// JWTDetector finds JWT-shaped tokens (two base64url JSON segments and a
// signature segment).
func JWTDetector() Detector { return &RegexDetector{name: "jwt", re: jwtRe} }

type pemDetector struct{}

// PrivateKeyDetector finds PEM private key blocks. A block whose end marker
// has not arrived yet is held back by the redactor and, at end of stream,
// redacted to the end of the input.
func PrivateKeyDetector() Detector { return pemDetector{} }

func (pemDetector) Name() string { return "private_key" }

func (pemDetector) Find(b []byte) []Span {
	var out []Span
	for _, loc := range pemRe.FindAllIndex(b, -1) {
		out = append(out, Span{loc[0], loc[1]})
	}
	return out
}

func (d pemDetector) Partial(b []byte) int {
	matched := d.Find(b)
	last := -1
	for _, loc := range pemBegin.FindAllIndex(b, -1) {
		inside := false
		for _, m := range matched {
			if loc[0] >= m.Start && loc[0] < m.End {
				inside = true
				break
			}
		}
		if !inside {
			last = loc[0]
			break // earliest unmatched begin: hold from there
		}
	}
	return last
}

// DefaultDetectors returns the built-in detectors.
func DefaultDetectors() []Detector {
	return []Detector{PrivateKeyDetector(), JWTDetector(), AWSAccessKeyDetector(), CardDetector(), EmailDetector()}
}
