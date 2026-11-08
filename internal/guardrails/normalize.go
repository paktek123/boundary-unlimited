// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package guardrails

import (
	"errors"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// MaxCommandLen is the hard maximum length in bytes of a command (raw or
// normalised) that is evaluated. Longer commands are blocked. It is a
// compile-time constant and cannot be raised by options.
const MaxCommandLen = 8 * 1024

// ErrInvalidCommand is returned by Normalise for input that must be blocked.
// The message never contains any part of the command.
var ErrInvalidCommand = errors.New("guardrails: command rejected")

// Normalise validates a raw command and returns its NFKC form, used as the
// second copy that rules are matched against (the raw copy is matched too).
//
// It returns ErrInvalidCommand for: invalid UTF-8, NUL and ASCII/C1 control
// characters (other than tab and line feed), bidirectional override and
// isolate characters and other Unicode format (Cf) characters such as
// zero-width characters, and input longer than maxLen bytes (before or after
// normalisation). maxLen is capped at MaxCommandLen; a value <= 0 selects
// MaxCommandLen. Tab and line feed are the only allowed control characters:
// carriage return is rejected.
func Normalise(raw []byte, maxLen int) (string, error) {
	if maxLen <= 0 || maxLen > MaxCommandLen {
		maxLen = MaxCommandLen
	}
	if len(raw) > maxLen || !utf8.Valid(raw) {
		return "", ErrInvalidCommand
	}
	if !allowedRunes(string(raw)) {
		return "", ErrInvalidCommand
	}
	out := norm.NFKC.String(string(raw))
	if len(out) > maxLen || !utf8.ValidString(out) || !allowedRunes(out) {
		return "", ErrInvalidCommand
	}
	return out, nil
}

func allowedRunes(s string) bool {
	for _, r := range s {
		if r == '\t' || r == '\n' {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || isBidi(r) {
			return false
		}
	}
	return true
}
