// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package notify

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits on Event fields. They keep payloads small and predictable.
const (
	MaxEventTypeLen = 64
	MaxEventIDLen   = 128
	MaxSummaryLen   = 512
)

// ErrInvalidEvent is returned for an Event that fails validation. The error
// text never echoes field values.
var ErrInvalidEvent = errors.New("notify: invalid event")

var eventTypeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

// Event is a notification payload. It must not carry secrets, credentials or
// command text: only identifiers and a short human summary.
type Event struct {
	// Type is a lower-case dotted name such as "access_request.created".
	Type      string    `json:"type"`
	RequestID string    `json:"request_id"`
	ScopeID   string    `json:"scope_id"`
	Timestamp time.Time `json:"timestamp"`
	// Summary is a short human-readable description.
	Summary string `json:"summary"`
}

// Notifier delivers events.
type Notifier interface {
	Notify(ctx context.Context, e Event) error
}

func validText(s string, max int, allowEmpty bool) bool {
	if s == "" {
		return allowEmpty
	}
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return false
		}
	}
	return true
}

// Validate checks the event fields.
func (e Event) Validate() error {
	switch {
	case len(e.Type) > MaxEventTypeLen || !eventTypeRe.MatchString(e.Type):
		return fmt.Errorf("%w: type", ErrInvalidEvent)
	case !validText(e.RequestID, MaxEventIDLen, false):
		return fmt.Errorf("%w: request id", ErrInvalidEvent)
	case !validText(e.ScopeID, MaxEventIDLen, false):
		return fmt.Errorf("%w: scope id", ErrInvalidEvent)
	case e.Timestamp.IsZero():
		return fmt.Errorf("%w: timestamp", ErrInvalidEvent)
	case !validText(e.Summary, MaxSummaryLen, true):
		return fmt.Errorf("%w: summary", ErrInvalidEvent)
	}
	return nil
}
