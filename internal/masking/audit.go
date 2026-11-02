// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package masking

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// EventType identifies a masking audit event.
type EventType string

// EventRedactions is emitted once per rule and time window with the number of
// redactions in that window.
const EventRedactions EventType = "masking.redactions"

// Errors returned by the audit helpers. Messages never carry caller input.
var (
	ErrInvalidAuditInput = errors.New("masking: invalid audit input")
	ErrSensitiveField    = errors.New("masking: audit field looks like a credential")
)

// Event is a counts-only audit event. It deliberately holds only the session
// id, rule id, detector type, redaction count, time window and principal id
// (security decision on #87, decision 2). Never add matched values,
// surrounding text, offsets, per-occurrence lengths or replacement text:
// TestEventStructHasOnlyAllowedFields enforces the field list.
type Event struct {
	Type        EventType
	SessionId   string
	RuleId      string
	Detector    string
	Count       int
	WindowStart time.Time
	WindowEnd   time.Time
	PrincipalId string
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

var sensitiveIDPattern = regexp.MustCompile(`(?i)(-----BEGIN |\bAKIA[0-9A-Z]{16}\b|\beyJ[A-Za-z0-9_-]{8,}\.|\bbearer\s+\S|\b(password|passwd|secret|token|api[_-]?key)\s*[=:])`)

// maxIDLen bounds identifiers so an id cannot smuggle free text.
const maxIDLen = 128

func checkID(s string) error {
	if s == "" || len(s) > maxIDLen {
		return ErrInvalidAuditInput
	}
	if strings.ContainsAny(s, "\r\n\x00") || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ErrInvalidAuditInput
	}
	if sensitiveIDPattern.MatchString(s) {
		return ErrSensitiveField
	}
	return nil
}

type counterKey struct{ rule, detector string }

// Aggregator counts redactions per rule and emits one Event per rule and time
// window; windows with no redactions emit nothing. It is safe for concurrent
// use. Windows are aligned to the first count after the previous window.
type Aggregator struct {
	sessionId, principalId string
	window                 time.Duration
	em                     Emitter
	now                    func() time.Time

	mu     sync.Mutex
	start  time.Time
	counts map[counterKey]int
}

// NewAggregator returns an Aggregator. window must be positive; now defaults
// to time.Now when nil.
func NewAggregator(sessionId, principalId string, window time.Duration, em Emitter, now func() time.Time) (*Aggregator, error) {
	if err := errors.Join(checkID(sessionId), checkID(principalId)); err != nil {
		return nil, fmt.Errorf("masking: invalid session or principal id: %w", firstErr(err))
	}
	if window <= 0 || em == nil {
		return nil, ErrInvalidAuditInput
	}
	if now == nil {
		now = time.Now
	}
	return &Aggregator{sessionId: sessionId, principalId: principalId, window: window, em: em, now: now, counts: map[counterKey]int{}}, nil
}

func firstErr(err error) error {
	if errors.Is(err, ErrSensitiveField) {
		return ErrSensitiveField
	}
	return ErrInvalidAuditInput
}

// Add records n redactions by the rule. If the current window has ended, it is
// emitted first. n <= 0 records nothing. Emit errors are returned and the
// window's counts are kept for the next attempt.
func (a *Aggregator) Add(ctx context.Context, ruleId, detector string, n int) error {
	if err := errors.Join(checkID(ruleId), checkID(detector)); err != nil {
		return firstErr(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if len(a.counts) > 0 && !now.Before(a.start.Add(a.window)) {
		if err := a.flushLocked(ctx, a.start.Add(a.window)); err != nil {
			return err
		}
	}
	if n <= 0 {
		return nil
	}
	if len(a.counts) == 0 {
		a.start = now
	}
	a.counts[counterKey{ruleId, detector}] += n
	return nil
}

// Flush emits the current window now (for example at session end).
func (a *Aggregator) Flush(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	end := a.now()
	if end.Before(a.start) {
		end = a.start
	}
	return a.flushLocked(ctx, end)
}

func (a *Aggregator) flushLocked(ctx context.Context, end time.Time) error {
	if len(a.counts) == 0 {
		return nil
	}
	keys := make([]counterKey, 0, len(a.counts))
	for k := range a.counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].rule != keys[j].rule {
			return keys[i].rule < keys[j].rule
		}
		return keys[i].detector < keys[j].detector
	})
	for _, k := range keys {
		e := Event{Type: EventRedactions, SessionId: a.sessionId, RuleId: k.rule, Detector: k.detector,
			Count: a.counts[k], WindowStart: a.start, WindowEnd: end, PrincipalId: a.principalId}
		if err := a.em.Emit(ctx, e); err != nil {
			return fmt.Errorf("masking: emit audit event: %w", err)
		}
		delete(a.counts, k)
	}
	return nil
}
