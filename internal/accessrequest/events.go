// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// EventType identifies one audit event per lifecycle transition.
type EventType string

const (
	EventCreate            EventType = "access-request.create"
	EventApprove           EventType = "access-request.approve"
	EventDeny              EventType = "access-request.deny"
	EventCancel            EventType = "access-request.cancel"
	EventExpire            EventType = "access-request.expire"
	EventOverlayAuthorized EventType = "access-request.overlay-authorized"
)

// ErrSensitiveField is returned by event constructors when a field looks like
// it carries a credential or token. The offending value is never included.
var ErrSensitiveField = errors.New("accessrequest: event field looks like a credential")

// Event is an audit event payload. It deliberately holds only identifiers,
// grant strings and timestamps. Do not add free-text fields such as the
// justification: TestEventStructHasOnlyAllowedFields enforces this.
type Event struct {
	Type        EventType
	RequestId   string
	RequesterId string
	// ApproverId is the acting user for approve, deny and cancel; empty for
	// create and expire.
	ApproverId string
	// Grants are the grant strings the event concerns; exactly one for
	// overlay-authorized.
	Grants []string
	At     time.Time
	// NotAfter is the hard end of access (approve and overlay-authorized).
	NotAfter time.Time
}

// Emitter publishes audit events. Its error is returned to the caller so a
// later wiring slice can fail closed (no grant takes effect unless the event
// was emitted).
type Emitter interface {
	Emit(ctx context.Context, e Event) error
}

// RecordingEmitter is a concurrency-safe Emitter fake that records events.
// If Err is set, Emit records nothing and returns it.
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
	e.Grants = append([]string(nil), e.Grants...)
	r.events = append(r.events, e)
	return nil
}

// Events returns a copy of the recorded events.
func (r *RecordingEmitter) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	for i, e := range r.events {
		e.Grants = append([]string(nil), e.Grants...)
		out[i] = e
	}
	return out
}

var sensitivePattern = regexp.MustCompile(`(?i)(-----BEGIN |\bAKIA[0-9A-Z]{16}\b|\beyJ[A-Za-z0-9_-]{8,}\.|\bbearer\s+\S|\bpassword\s*[=:]|\bpasswd\s*[=:]|\bsecret\s*[=:]|\btoken\s*[=:]|\bapi[_-]?key\s*[=:]|\bat_[A-Za-z0-9]{10,})`)

func checkClean(vals ...string) error {
	for _, v := range vals {
		if sensitivePattern.MatchString(v) {
			return ErrSensitiveField
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("%w: control characters", ErrInvalidInput)
		}
	}
	return nil
}

func newEvent(t EventType, r Request, actor string, at time.Time, grants []string, notAfter time.Time) (Event, error) {
	if strings.TrimSpace(r.Id) == "" || strings.TrimSpace(r.RequesterId) == "" {
		return Event{}, fmt.Errorf("%w: missing request or requester id", ErrInvalidInput)
	}
	if at.IsZero() {
		return Event{}, fmt.Errorf("%w: zero time", ErrInvalidInput)
	}
	if err := checkClean(append([]string{r.Id, r.RequesterId, actor}, grants...)...); err != nil {
		return Event{}, err
	}
	return Event{
		Type: t, RequestId: r.Id, RequesterId: r.RequesterId, ApproverId: actor,
		Grants: append([]string(nil), grants...), At: at, NotAfter: notAfter,
	}, nil
}

// NewCreateEvent builds the event for a newly created request.
func NewCreateEvent(r Request) (Event, error) {
	return newEvent(EventCreate, r, "", r.CreatedAt, r.Grants, time.Time{})
}

// NewApproveEvent builds the event for an approved request (state must be
// approved; the approver and expiry come from the request).
func NewApproveEvent(r Request) (Event, error) {
	if r.State != StateApproved || strings.TrimSpace(r.DecidedBy) == "" || r.ExpiresAt.IsZero() {
		return Event{}, fmt.Errorf("%w: request is not approved", ErrInvalidTransition)
	}
	return newEvent(EventApprove, r, r.DecidedBy, r.DecidedAt, r.Grants, r.ExpiresAt)
}

// NewDenyEvent builds the event for a denied request.
func NewDenyEvent(r Request) (Event, error) {
	if r.State != StateDenied || strings.TrimSpace(r.DecidedBy) == "" {
		return Event{}, fmt.Errorf("%w: request is not denied", ErrInvalidTransition)
	}
	return newEvent(EventDeny, r, r.DecidedBy, r.DecidedAt, r.Grants, time.Time{})
}

// NewCancelEvent builds the event for a cancelled request.
func NewCancelEvent(r Request) (Event, error) {
	if r.State != StateCancelled || strings.TrimSpace(r.DecidedBy) == "" {
		return Event{}, fmt.Errorf("%w: request is not cancelled", ErrInvalidTransition)
	}
	return newEvent(EventCancel, r, r.DecidedBy, r.DecidedAt, r.Grants, time.Time{})
}

// NewExpireEvent builds the event for an expired request, observed at now.
func NewExpireEvent(r Request, now time.Time) (Event, error) {
	if r.State != StateExpired {
		return Event{}, fmt.Errorf("%w: request is not expired", ErrInvalidTransition)
	}
	return newEvent(EventExpire, r, "", now, r.Grants, r.ExpiresAt)
}

// NewOverlayAuthorizedEvent builds the event recorded when one granted grant
// string authorizes access at now. The request must be active at now and the
// grant must be one of the approved grants.
func NewOverlayAuthorizedEvent(r Request, grant string, now time.Time) (Event, error) {
	if !r.Active(now) {
		return Event{}, fmt.Errorf("%w: request is not active", ErrInvalidTransition)
	}
	found := false
	for _, g := range r.Grants {
		if g == grant {
			found = true
			break
		}
	}
	if !found {
		return Event{}, fmt.Errorf("%w: grant was not part of the request", ErrInvalidInput)
	}
	return newEvent(EventOverlayAuthorized, r, r.DecidedBy, now, []string{grant}, r.ExpiresAt)
}
