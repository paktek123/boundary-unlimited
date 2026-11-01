// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package accessrequest is a pure-Go domain model for just-in-time access
// requests: a lifecycle state machine with no persistence, API or wiring.
// Nothing in the controller or worker references it yet, so it enables no
// capability. Every function fails closed: invalid input or an unknown state
// returns an error and the request is returned unchanged.
package accessrequest

import (
	"fmt"
	"strings"
	"time"
)

// State is the lifecycle state of a Request.
type State string

const (
	StatePending   State = "pending"
	StateApproved  State = "approved"
	StateDenied    State = "denied"
	StateCancelled State = "cancelled"
	StateExpired   State = "expired"
	StateRevoked   State = "revoked"
)

// Defaults for Options.
const (
	DefaultMaxDuration      = 8 * time.Hour
	DefaultMaxPendingAge    = 24 * time.Hour
	DefaultMaxJustification = 1024
	DefaultMaxGrants        = 64
)

// Clock supplies the current time; lifecycle code never calls time.Now.
type Clock interface {
	Now() time.Time
}

// SystemClock is the Clock backed by the wall clock.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now() }

// Terminal reports whether s can never change again.
func (s State) Terminal() bool {
	switch s {
	case StateDenied, StateCancelled, StateExpired, StateRevoked:
		return true
	}
	return false
}

func (s State) valid() bool {
	return s.Terminal() || s == StatePending || s == StateApproved
}

// Request is a time-bounded access request. Grants are opaque strings that
// the caller validates. Request is a value type: lifecycle functions return a
// modified copy and never mutate their argument.
type Request struct {
	Id          string
	RequesterId string
	ScopeId     string
	// Grants are the target/role grant strings requested.
	Grants        []string
	Justification string
	// Duration is how long access lasts once approved.
	Duration  time.Duration
	State     State
	CreatedAt time.Time
	// DecidedAt and DecidedBy are set by Approve, Deny, Cancel and Revoke.
	DecidedAt time.Time
	DecidedBy string
	// ExpiresAt is set on approval; zero while pending.
	ExpiresAt time.Time
	// Version is for optimistic concurrency in a Repository.
	Version uint32
}

// Options configure limits.
type Options struct {
	MaxDuration      time.Duration
	MaxPendingAge    time.Duration
	MaxJustification int
	MaxGrants        int
}

// Option modifies Options.
type Option func(*Options)

// WithMaxDuration caps the requested duration.
func WithMaxDuration(d time.Duration) Option { return func(o *Options) { o.MaxDuration = d } }

// WithMaxPendingAge sets how long a request may stay undecided.
func WithMaxPendingAge(d time.Duration) Option { return func(o *Options) { o.MaxPendingAge = d } }

// WithMaxJustification caps the justification length in bytes.
func WithMaxJustification(n int) Option { return func(o *Options) { o.MaxJustification = n } }

// WithMaxGrants caps the number of requested grants.
func WithMaxGrants(n int) Option { return func(o *Options) { o.MaxGrants = n } }

func getOpts(opt ...Option) Options {
	o := Options{
		MaxDuration:      DefaultMaxDuration,
		MaxPendingAge:    DefaultMaxPendingAge,
		MaxJustification: DefaultMaxJustification,
		MaxGrants:        DefaultMaxGrants,
	}
	for _, f := range opt {
		f(&o)
	}
	return o
}

func (o Options) valid() error {
	if o.MaxDuration <= 0 || o.MaxPendingAge <= 0 || o.MaxJustification <= 0 || o.MaxGrants <= 0 {
		return fmt.Errorf("%w: limits must be positive", ErrInvalidInput)
	}
	return nil
}

// New validates the input and returns a pending Request created at clock.Now().
func New(clock Clock, id, requesterId, scopeId string, grants []string, justification string, duration time.Duration, opt ...Option) (Request, error) {
	o := getOpts(opt...)
	if err := o.valid(); err != nil {
		return Request{}, err
	}
	if clock == nil {
		return Request{}, fmt.Errorf("%w: missing clock", ErrInvalidInput)
	}
	switch {
	case strings.TrimSpace(id) == "":
		return Request{}, fmt.Errorf("%w: missing id", ErrInvalidInput)
	case strings.TrimSpace(requesterId) == "":
		return Request{}, fmt.Errorf("%w: missing requester", ErrInvalidInput)
	case strings.TrimSpace(scopeId) == "":
		return Request{}, fmt.Errorf("%w: missing scope", ErrInvalidInput)
	case len(grants) == 0:
		return Request{}, fmt.Errorf("%w: at least one grant is required", ErrInvalidInput)
	case len(grants) > o.MaxGrants:
		return Request{}, fmt.Errorf("%w: too many grants", ErrInvalidInput)
	case strings.TrimSpace(justification) == "":
		return Request{}, fmt.Errorf("%w: justification is required", ErrInvalidInput)
	case len(justification) > o.MaxJustification:
		return Request{}, fmt.Errorf("%w: justification too long", ErrInvalidInput)
	case duration <= 0:
		return Request{}, fmt.Errorf("%w: duration must be positive", ErrInvalidInput)
	case duration > o.MaxDuration:
		return Request{}, ErrDurationTooLong
	}
	for _, g := range grants {
		if strings.TrimSpace(g) == "" {
			return Request{}, fmt.Errorf("%w: empty grant", ErrInvalidInput)
		}
	}
	now := clock.Now()
	if now.IsZero() {
		return Request{}, fmt.Errorf("%w: clock returned zero time", ErrInvalidInput)
	}
	return Request{
		Id:            id,
		RequesterId:   requesterId,
		ScopeId:       scopeId,
		Grants:        append([]string(nil), grants...),
		Justification: justification,
		Duration:      duration,
		State:         StatePending,
		CreatedAt:     now,
	}, nil
}

// check validates fields common to every transition.
func check(r Request, actorId string, now time.Time) error {
	if !r.State.valid() {
		return fmt.Errorf("%w: %q", ErrInvalidState, r.State)
	}
	if strings.TrimSpace(r.RequesterId) == "" || r.CreatedAt.IsZero() {
		return fmt.Errorf("%w: malformed request", ErrInvalidInput)
	}
	if strings.TrimSpace(actorId) == "" {
		return fmt.Errorf("%w: missing actor", ErrInvalidInput)
	}
	if now.IsZero() {
		return fmt.Errorf("%w: zero time", ErrInvalidInput)
	}
	return nil
}

func requirePending(r Request, now time.Time, o Options) error {
	if r.State != StatePending {
		return fmt.Errorf("%w: %s -> decision", ErrInvalidTransition, r.State)
	}
	if !now.Before(r.CreatedAt.Add(o.MaxPendingAge)) {
		return ErrPendingExpired
	}
	return nil
}

// Approve moves a pending request to approved and sets ExpiresAt to
// now+Duration. The requester can never approve their own request.
func Approve(r Request, approverId string, now time.Time, opt ...Option) (Request, error) {
	o := getOpts(opt...)
	if err := o.valid(); err != nil {
		return r, err
	}
	if err := check(r, approverId, now); err != nil {
		return r, err
	}
	if approverId == r.RequesterId {
		return r, ErrSelfApproval
	}
	if err := requirePending(r, now, o); err != nil {
		return r, err
	}
	if r.Duration <= 0 {
		return r, fmt.Errorf("%w: duration must be positive", ErrInvalidInput)
	}
	if r.Duration > o.MaxDuration {
		return r, ErrDurationTooLong
	}
	exp := now.Add(r.Duration)
	if limit := r.CreatedAt.Add(o.MaxPendingAge + r.Duration); exp.After(limit) {
		exp = limit
	}
	r.State, r.DecidedAt, r.DecidedBy, r.ExpiresAt = StateApproved, now, approverId, exp
	return r, nil
}

// Deny moves a pending request to denied. The requester cannot deny their own
// request; they use Cancel.
func Deny(r Request, denierId string, now time.Time, opt ...Option) (Request, error) {
	o := getOpts(opt...)
	if err := o.valid(); err != nil {
		return r, err
	}
	if err := check(r, denierId, now); err != nil {
		return r, err
	}
	if denierId == r.RequesterId {
		return r, ErrSelfApproval
	}
	if err := requirePending(r, now, o); err != nil {
		return r, err
	}
	r.State, r.DecidedAt, r.DecidedBy = StateDenied, now, denierId
	return r, nil
}

// Cancel moves a pending request to cancelled. Only the requester may cancel.
func Cancel(r Request, actorId string, now time.Time, opt ...Option) (Request, error) {
	o := getOpts(opt...)
	if err := o.valid(); err != nil {
		return r, err
	}
	if err := check(r, actorId, now); err != nil {
		return r, err
	}
	if actorId != r.RequesterId {
		return r, ErrNotRequester
	}
	if err := requirePending(r, now, o); err != nil {
		return r, err
	}
	r.State, r.DecidedAt, r.DecidedBy = StateCancelled, now, actorId
	return r, nil
}

// Revoke moves an approved request, still before its expiry, to revoked.
func Revoke(r Request, revokerId string, now time.Time) (Request, error) {
	if err := check(r, revokerId, now); err != nil {
		return r, err
	}
	if r.State != StateApproved {
		return r, fmt.Errorf("%w: %s -> revoked", ErrInvalidTransition, r.State)
	}
	if !now.Before(r.ExpiresAt) {
		return r, fmt.Errorf("%w: already past expiry", ErrInvalidTransition)
	}
	r.State, r.DecidedAt, r.DecidedBy = StateRevoked, now, revokerId
	return r, nil
}

// Expire is idempotent. It moves a pending request past its maximum age, or
// an approved request at or past ExpiresAt, to expired. Any other request is
// returned unchanged without error. An unknown state or malformed request is
// an error.
func Expire(r Request, now time.Time, opt ...Option) (Request, error) {
	o := getOpts(opt...)
	if err := o.valid(); err != nil {
		return r, err
	}
	if !r.State.valid() {
		return r, fmt.Errorf("%w: %q", ErrInvalidState, r.State)
	}
	if now.IsZero() {
		return r, fmt.Errorf("%w: zero time", ErrInvalidInput)
	}
	switch r.State {
	case StatePending:
		if r.CreatedAt.IsZero() {
			return r, fmt.Errorf("%w: malformed request", ErrInvalidInput)
		}
		if !now.Before(r.CreatedAt.Add(o.MaxPendingAge)) {
			r.State = StateExpired
		}
	case StateApproved:
		if r.ExpiresAt.IsZero() {
			return r, fmt.Errorf("%w: approved request without expiry", ErrInvalidInput)
		}
		if !now.Before(r.ExpiresAt) {
			r.State = StateExpired
		}
	}
	return r, nil
}

// Active reports whether the request currently confers access: approved and
// strictly before ExpiresAt. Anything else, including malformed data, is false.
func (r Request) Active(now time.Time) bool {
	return r.State == StateApproved && !r.ExpiresAt.IsZero() && !now.IsZero() && now.Before(r.ExpiresAt)
}
