// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"fmt"
	"reflect"
	"time"
)

// NotifyKind is the lifecycle step a Notifier is told about. It is declared
// here, not imported from internal/notify, to avoid an import cycle.
type NotifyKind string

// Notify kinds.
const (
	NotifyRequested NotifyKind = "requested"
	NotifyApproved  NotifyKind = "approved"
	NotifyDenied    NotifyKind = "denied"
	NotifyCancelled NotifyKind = "cancelled"
	NotifyExpired   NotifyKind = "expired"
)

// AuditSink receives the audit event of every transition before the
// transition is committed.
type AuditSink = Emitter

// Notifier is told about committed transitions. It receives a copy of the
// request with the justification removed. Its errors and panics are ignored.
type Notifier interface {
	Notify(ctx context.Context, kind NotifyKind, r Request) error
}

// IDGenerator returns a new unique request id.
type IDGenerator func() (string, error)

// Actor is the acting user, resolved by the caller. This package does no
// lookups and trusts nothing but these values.
type Actor struct {
	Id string
	// CanApprove is true when the actor holds ApproveAction on the request
	// scope.
	CanApprove bool
	// Grants are the actor's resolved grant strings.
	Grants []string
}

// ServiceConfig carries the Service dependencies. Repo, Audit, Clock and
// NewId are required; Notifier may be nil. Policy.MaxTTL must be positive.
type ServiceConfig struct {
	Repo     Repository
	Policy   ApprovalPolicy
	Audit    AuditSink
	Notifier Notifier
	// NotifyTimeout bounds one Notify call. Zero selects DefaultNotifyTimeout.
	// A notifier that ignores its context is abandoned at the timeout.
	NotifyTimeout time.Duration
	Clock         Clock
	NewId         IDGenerator
	// Options are the lifecycle limits (pending age, justification length,
	// grant count). The duration cap is always Policy.MaxTTL.
	Options []Option
}

// Service composes the state machine, approval policy, audit events and
// notifications. It only enforces; nothing exposes it yet.
type Service struct {
	cfg ServiceConfig
}

// NewService validates cfg and returns a Service. It fails closed on any
// missing dependency or non-positive MaxTTL.
func NewService(cfg ServiceConfig) (*Service, error) {
	if isNil(cfg.Repo) || isNil(cfg.Audit) || isNil(cfg.Clock) || cfg.NewId == nil {
		return nil, fmt.Errorf("%w: repository, audit sink, clock and id generator are required", ErrInvalidInput)
	}
	if cfg.Policy.MaxTTL <= 0 {
		return nil, fmt.Errorf("%w: max TTL must be positive", ErrInvalidPolicy)
	}
	opts := append(append([]Option(nil), cfg.Options...), WithMaxDuration(cfg.Policy.MaxTTL))
	if err := getOpts(opts...).valid(); err != nil {
		return nil, err
	}
	cfg.Options = opts
	return &Service{cfg: cfg}, nil
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// Create stores a new pending request. The duration may not exceed the policy
// maximum TTL. The grants are bound to the request by their hash and cannot be
// changed afterwards (there is no update method).
func (s *Service) Create(ctx context.Context, actor Actor, scopeId string, grants []string, justification string, duration time.Duration) (Request, error) {
	id, err := s.cfg.NewId()
	if err != nil {
		return Request{}, fmt.Errorf("%w: id generation failed", ErrInvalidInput)
	}
	r, err := New(s.cfg.Clock, id, actor.Id, scopeId, grants, justification, duration, s.cfg.Options...)
	if err != nil {
		return Request{}, err
	}
	r.GrantHash = GrantHash(r.Grants)
	ev, err := NewCreateEvent(r)
	if err != nil {
		return Request{}, err
	}
	if err := s.emit(ctx, ev); err != nil {
		return Request{}, errAudit
	}
	out, err := s.cfg.Repo.Create(ctx, r)
	if err != nil {
		return Request{}, err
	}
	s.notify(ctx, NotifyRequested, out)
	return out, nil
}

// Approve validates and records an approval: the actor may not be the
// requester, must hold ApproveAction and every requested grant, and the grants
// must still match the hash recorded at creation.
func (s *Service) Approve(ctx context.Context, actor Actor, id string) (Request, error) {
	return s.decide(ctx, id, NotifyApproved, func(r Request, now time.Time) (Request, Event, error) {
		out, err := RecordApproval(r, ApproverContext(actor), now, s.cfg.Policy, s.cfg.Options...)
		if err != nil {
			return r, Event{}, err
		}
		ev, err := NewApproveEvent(out)
		return out, ev, err
	})
}

// Deny denies a pending request. Like approval it needs ApproveAction, and the
// requester cannot deny their own request (they cancel it).
func (s *Service) Deny(ctx context.Context, actor Actor, id string) (Request, error) {
	return s.decide(ctx, id, NotifyDenied, func(r Request, now time.Time) (Request, Event, error) {
		if !actor.CanApprove {
			return r, Event{}, ErrApproverNotAuthorized
		}
		out, err := Deny(r, actor.Id, now, s.cfg.Options...)
		if err != nil {
			return r, Event{}, err
		}
		ev, err := NewDenyEvent(out)
		return out, ev, err
	})
}

// Cancel cancels a pending request. Only the requester may cancel.
func (s *Service) Cancel(ctx context.Context, actor Actor, id string) (Request, error) {
	return s.decide(ctx, id, NotifyCancelled, func(r Request, now time.Time) (Request, Event, error) {
		out, err := Cancel(r, actor.Id, now, s.cfg.Options...)
		if err != nil {
			return r, Event{}, err
		}
		ev, err := NewCancelEvent(out)
		return out, ev, err
	})
}

var errAudit = fmt.Errorf("accessrequest: audit event could not be emitted; nothing changed")

// decide loads the request, applies the transition, emits the audit event
// BEFORE committing, then commits with the version check and notifies. If the
// audit sink fails nothing is written. A commit conflict after the event was
// emitted is reported to the caller; the extra event is a known limit of
// emit-before-commit and is preferable to an unaudited change.
func (s *Service) decide(ctx context.Context, id string, kind NotifyKind, f func(Request, time.Time) (Request, Event, error)) (Request, error) {
	cur, err := s.cfg.Repo.Get(ctx, id)
	if err != nil {
		return Request{}, err
	}
	next, ev, err := f(cur, s.cfg.Clock.Now())
	if err != nil {
		return cur, err
	}
	if err := s.emit(ctx, ev); err != nil {
		return cur, errAudit
	}
	out, err := s.cfg.Repo.Update(ctx, next)
	if err != nil {
		return cur, err
	}
	s.notify(ctx, kind, out)
	return out, nil
}

// emit publishes ev; an error or panic is reported as errAudit.
func (s *Service) emit(ctx context.Context, ev Event) (err error) {
	defer func() {
		if recover() != nil {
			err = errAudit
		}
	}()
	if s.cfg.Audit.Emit(ctx, ev) != nil {
		return errAudit
	}
	return nil
}

// notify tells the Notifier about a committed change; see deliverNotice.
func (s *Service) notify(ctx context.Context, kind NotifyKind, r Request) {
	deliverNotice(ctx, s.cfg.Notifier, s.cfg.Audit, s.cfg.NotifyTimeout, kind, r)
}

// DefaultNotifyTimeout bounds one Notifier call when none is configured.
const DefaultNotifyTimeout = 15 * time.Second

// deliverNotice tells n about a committed change. It never changes request
// state and never returns an error: the justification is removed, the call is
// bounded by timeout, and an error, panic or timeout is recorded as an
// access-request.notify-failed audit event (best effort; identifiers only,
// never the error text, which could carry a URL or secret).
func deliverNotice(ctx context.Context, n Notifier, em Emitter, timeout time.Duration, kind NotifyKind, r Request) {
	if isNil(n) {
		return
	}
	if timeout <= 0 {
		timeout = DefaultNotifyTimeout
	}
	r.Justification = ""
	r.Grants = append([]string(nil), r.Grants...)
	nctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan bool, 1) // buffered: an abandoned notifier can still finish
	go func() {
		ok := false
		defer func() {
			_ = recover() // the value is discarded: it may hold secrets
			done <- ok
		}()
		ok = n.Notify(nctx, kind, r) == nil
	}()
	var ok bool
	select {
	case ok = <-done:
	case <-nctx.Done():
		select {
		case ok = <-done:
		default:
		}
	}
	if ok {
		return
	}
	auditNotifyFailure(ctx, em, r)
}

func auditNotifyFailure(ctx context.Context, em Emitter, r Request) {
	if isNil(em) {
		return
	}
	defer func() { _ = recover() }()
	ev, err := NewNotifyFailedEvent(r, time.Now())
	if err != nil {
		return
	}
	_ = em.Emit(ctx, ev)
}
