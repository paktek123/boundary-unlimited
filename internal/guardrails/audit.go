// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package guardrails

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
)

// EventType identifies a guardrails audit event.
type EventType string

// Event types.
const (
	// EventBlocked: a command matched a deny rule (or was rejected as
	// malformed) and was not forwarded. Count is the number of identical
	// consecutive blocks this event stands for (at least 1).
	EventBlocked EventType = "guardrails.blocked"
	// EventReviewRequested: a command matched a require_review rule.
	EventReviewRequested EventType = "guardrails.review_requested"
	// EventSessionTerminated: the session ended after the Nth blocked command.
	EventSessionTerminated EventType = "guardrails.session_terminated"
	// EventInteractiveBestEffort: emitted at session start when the operator
	// opted into allow_interactive; enforcement on interactive input is best
	// effort only.
	EventInteractiveBestEffort EventType = "guardrails.interactive_best_effort"
)

// Decision is what was done with the command or session.
type Decision string

// Decisions.
const (
	DecisionBlocked           Decision = "blocked"
	DecisionReviewRequested   Decision = "review_requested"
	DecisionTerminated        Decision = "terminated"
	DecisionAllowedBestEffort Decision = "allowed_best_effort"
)

// Errors returned by the event constructors. Messages never carry caller input.
var (
	ErrInvalidAuditInput = errors.New("guardrails: invalid audit input")
	ErrSensitiveField    = errors.New("guardrails: audit field looks like a credential")
)

// Event is a counts-only audit event. It deliberately holds only the session
// id, rule id, rule-set hash (version), action, decision, count, principal id
// and timestamp (security decision 2 on #88). Never add command text, a
// fragment, a match offset, a length, or any hash of the command:
// TestEventStructHasOnlyAllowedFields enforces the field list.
type Event struct {
	Type        EventType
	SessionId   string
	RuleId      string // empty when no rule decided (for example malformed input)
	RuleSetHash string // the compiled rule-set hash, never a command hash
	Action      Action // empty when no rule action applies
	Decision    Decision
	Count       int
	PrincipalId string
	Timestamp   time.Time
}

// Emitter publishes audit events. Its error is returned to the caller so a
// wiring slice can fail closed.
type Emitter interface {
	Emit(ctx context.Context, e Event) error
}

// RecordingEmitter is a concurrency-safe Emitter fake. If Err is set, Emit
// records nothing and returns it.
type RecordingEmitter struct {
	mu     sync.Mutex
	Err    error
	events []Event
}

// Emit implements Emitter.
func (r *RecordingEmitter) Emit(_ context.Context, e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Err != nil {
		return r.Err
	}
	r.events = append(r.events, e)
	return nil
}

// Events returns a copy of the recorded events.
func (r *RecordingEmitter) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

var (
	sensitiveIDPattern = regexp.MustCompile(`(?i)(-----BEGIN |\bAKIA[0-9A-Z]{16}\b|\beyJ[A-Za-z0-9_-]{8,}\.|\bbearer\s+\S|\b(password|passwd|secret|token|api[_-]?key)\s*[=:])`)
	hashPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func checkID(s string, optional bool) error {
	if s == "" {
		if optional {
			return nil
		}
		return ErrInvalidAuditInput
	}
	if len(s) > MaxRuleIDLen {
		return ErrInvalidAuditInput
	}
	if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ErrInvalidAuditInput
	}
	if sensitiveIDPattern.MatchString(s) {
		return ErrSensitiveField
	}
	return nil
}

func newEvent(t EventType, sessionID, principalID, ruleID, hash string, action Action, d Decision, count int, ts time.Time) (Event, error) {
	for _, err := range []error{
		checkID(sessionID, false), checkID(principalID, false), checkID(ruleID, true),
	} {
		if err != nil {
			return Event{}, err
		}
	}
	if !hashPattern.MatchString(hash) || count < 1 || ts.IsZero() {
		return Event{}, ErrInvalidAuditInput
	}
	switch action {
	case "", ActionDeny, ActionRequireReview:
	default:
		return Event{}, ErrInvalidAuditInput
	}
	return Event{Type: t, SessionId: sessionID, RuleId: ruleID, RuleSetHash: hash, Action: action,
		Decision: d, Count: count, PrincipalId: principalID, Timestamp: ts.UTC()}, nil
}

// NewBlockedEvent builds an EventBlocked. ruleID may be empty for a command
// rejected as malformed or by an allow-list miss. count (>= 1) is the number
// of identical blocks the event stands for; repeated blocks are counted, not
// logged one by one.
func NewBlockedEvent(sessionID, principalID, ruleID, ruleSetHash string, count int, ts time.Time) (Event, error) {
	action := Action("")
	if ruleID != "" {
		action = ActionDeny
	}
	return newEvent(EventBlocked, sessionID, principalID, ruleID, ruleSetHash, action, DecisionBlocked, count, ts)
}

// NewReviewRequestedEvent builds an EventReviewRequested. ruleID is required.
func NewReviewRequestedEvent(sessionID, principalID, ruleID, ruleSetHash string, ts time.Time) (Event, error) {
	if ruleID == "" {
		return Event{}, ErrInvalidAuditInput
	}
	return newEvent(EventReviewRequested, sessionID, principalID, ruleID, ruleSetHash, ActionRequireReview, DecisionReviewRequested, 1, ts)
}

// NewSessionTerminatedEvent builds an EventSessionTerminated; blocks is the
// number of blocked commands that ended the session.
func NewSessionTerminatedEvent(sessionID, principalID, ruleSetHash string, blocks int, ts time.Time) (Event, error) {
	return newEvent(EventSessionTerminated, sessionID, principalID, "", ruleSetHash, "", DecisionTerminated, blocks, ts)
}

// NewInteractiveBestEffortEvent builds the session-start EventInteractiveBestEffort.
func NewInteractiveBestEffortEvent(sessionID, principalID, ruleSetHash string, ts time.Time) (Event, error) {
	return newEvent(EventInteractiveBestEffort, sessionID, principalID, "", ruleSetHash, "", DecisionAllowedBestEffort, 1, ts)
}
