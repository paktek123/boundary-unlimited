// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbook

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
)

// EventType identifies a runbook audit event.
type EventType string

// Event types.
const (
	EventRunRequested EventType = "runbook.run_requested"
	EventRunStarted   EventType = "runbook.run_started"
	EventRunFinished  EventType = "runbook.run_finished"
	EventRunRejected  EventType = "runbook.run_rejected"
)

// Outcome is the result recorded on finished and rejected events.
type Outcome string

// Outcomes.
const (
	OutcomeNone     Outcome = ""
	OutcomeSuccess  Outcome = "success"
	OutcomeFailure  Outcome = "failure"
	OutcomeRejected Outcome = "rejected"
)

// Errors returned by the event constructor. Messages never carry caller input.
var (
	ErrInvalidAuditInput = errors.New("runbook: invalid audit input")
	ErrSensitiveField    = errors.New("runbook: audit field looks like a credential")
)

// Limits that keep events small and free of smuggled free text.
const (
	maxIDLen       = 256
	maxAuditParams = 64
)

// Event is a names-only audit event (safeguard 6 of the security decision on
// #89). It deliberately holds only identifiers, the Git commit SHA, the
// script SHA-256, parameter NAMES, outcome, time and the lint-pass-marker
// flag. Never add a parameter value, a hash of an individual value, or the
// approval-binding parameter hash: TestEventStructHasOnlyAllowedFields
// enforces the field list.
type Event struct {
	Type           EventType
	RunbookId      string
	CommitSHA      string // 40 lowercase hex Git commit
	ScriptSHA256   string // 64 lowercase hex hash of the script, never of a value
	ParamNames     []string
	PrincipalId    string
	TargetId       string
	SessionId      string
	Outcome        Outcome
	Timestamp      time.Time
	LintPassMarker bool
}

// EventInput is what a caller supplies to NewEvent.
type EventInput struct {
	Type           EventType
	RunbookId      string
	CommitSHA      string
	ScriptSHA256   string
	Params         Validated // only the names are read
	PrincipalId    string
	TargetId       string
	SessionId      string // optional: empty before a session exists
	Outcome        Outcome
	Timestamp      time.Time
	LintPassMarker bool
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
	e.ParamNames = append([]string(nil), e.ParamNames...)
	r.events = append(r.events, e)
	return nil
}

// Events returns a copy of the recorded events.
func (r *RecordingEmitter) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	for i, e := range r.events {
		e.ParamNames = append([]string(nil), e.ParamNames...)
		out[i] = e
	}
	return out
}

var (
	sensitiveIDPattern = regexp.MustCompile(`(?i)(-----BEGIN |\bAKIA[0-9A-Z]{16}\b|\beyJ[A-Za-z0-9_-]{8,}\.|\bbearer\s+\S|\b(password|passwd|secret|token|api[_-]?key)\s*[=:])`)
	sha1HexRE          = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256HexRE        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func checkID(s string, optional bool) error {
	if s == "" {
		if optional {
			return nil
		}
		return ErrInvalidAuditInput
	}
	if len(s) > maxIDLen || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ErrInvalidAuditInput
	}
	if sensitiveIDPattern.MatchString(s) {
		return ErrSensitiveField
	}
	return nil
}

// NewEvent validates the input and builds an Event carrying parameter names
// only. It never reads a parameter value. Errors never include caller input.
func NewEvent(in EventInput) (e Event, err error) {
	defer func() {
		if recover() != nil {
			e, err = Event{}, ErrInvalidAuditInput
		}
	}()
	switch in.Type {
	case EventRunRequested, EventRunStarted, EventRunFinished, EventRunRejected:
	default:
		return Event{}, ErrInvalidAuditInput
	}
	switch in.Outcome {
	case OutcomeNone, OutcomeSuccess, OutcomeFailure, OutcomeRejected:
	default:
		return Event{}, ErrInvalidAuditInput
	}
	if (in.Type == EventRunFinished || in.Type == EventRunRejected) && in.Outcome == OutcomeNone {
		return Event{}, ErrInvalidAuditInput
	}
	if in.Timestamp.IsZero() {
		return Event{}, ErrInvalidAuditInput
	}
	for _, id := range []struct {
		v   string
		opt bool
	}{{in.RunbookId, false}, {in.PrincipalId, false}, {in.TargetId, false}, {in.SessionId, true}} {
		if err := checkID(id.v, id.opt); err != nil {
			return Event{}, err
		}
	}
	if !sha1HexRE.MatchString(in.CommitSHA) || !sha256HexRE.MatchString(in.ScriptSHA256) {
		return Event{}, ErrInvalidAuditInput
	}
	names := in.Params.Names()
	if len(names) > maxAuditParams {
		return Event{}, ErrInvalidAuditInput
	}
	for _, n := range names {
		if !paramNameRE.MatchString(n) || len(n) > MaxNameLen {
			return Event{}, ErrInvalidAuditInput
		}
	}
	return Event{
		Type:           in.Type,
		RunbookId:      in.RunbookId,
		CommitSHA:      in.CommitSHA,
		ScriptSHA256:   in.ScriptSHA256,
		ParamNames:     names,
		PrincipalId:    in.PrincipalId,
		TargetId:       in.TargetId,
		SessionId:      in.SessionId,
		Outcome:        in.Outcome,
		Timestamp:      in.Timestamp,
		LintPassMarker: in.LintPassMarker,
	}, nil
}
