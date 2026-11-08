// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Sweeper expires pending requests past their maximum age and approved
// requests past ExpiresAt. It is safe to run repeatedly and concurrently.
//
// Audit: before a request is expired, the Sweeper emits an access-request.expire
// event to Emitter and skips the request (state unchanged) if emitting fails
// or panics. An event emitted before a lost version race is acceptable and may
// be repeated when the request is retried, exactly as in Service. A Sweeper
// without an Emitter fails closed unless it was built with WithoutAudit.
type Sweeper struct {
	Repo Repository
	Opts []Option
	// Emitter is the audit sink; required unless WithoutAudit was used.
	Emitter Emitter

	noAudit bool
}

// SweeperOption configures NewSweeper.
type SweeperOption func(*Sweeper)

// WithoutAudit explicitly allows a Sweeper with no audit emitter. Expiries
// then change state without an audit event; use it only in tests or where
// auditing is done elsewhere.
func WithoutAudit() SweeperOption { return func(s *Sweeper) { s.noAudit = true } }

// WithSweepOptions sets the policy options passed to Expire.
func WithSweepOptions(o ...Option) SweeperOption {
	return func(s *Sweeper) { s.Opts = append([]Option(nil), o...) }
}

// NewSweeper returns a Sweeper. A nil or typed-nil emitter is an error unless
// WithoutAudit is given.
func NewSweeper(repo Repository, em Emitter, opt ...SweeperOption) (*Sweeper, error) {
	s := &Sweeper{Repo: repo, Emitter: em}
	for _, o := range opt {
		o(s)
	}
	if isNil(repo) {
		return nil, fmt.Errorf("%w: repository is required", ErrInvalidInput)
	}
	if isNil(em) {
		if !s.noAudit {
			return nil, fmt.Errorf("%w: audit emitter is required", ErrInvalidInput)
		}
		s.Emitter = nil
	}
	return s, nil
}

// SweepResult counts what one run did.
type SweepResult struct {
	Expired int
	// Skipped counts requests left for a later run after a version conflict
	// that persisted through one retry.
	Skipped int
}

// Run lists pending and approved requests and applies Expire to those that
// are due. A version conflict is retried once (re-reading the request); if it
// conflicts again the request is skipped. Denied, cancelled, revoked and
// already expired requests are never listed or touched. If ctx ends, Run
// stops and returns ctx.Err() with the partial result.
func (s *Sweeper) Run(ctx context.Context, now time.Time) (SweepResult, error) {
	var res SweepResult
	if s == nil || s.Repo == nil {
		return res, fmt.Errorf("%w: repository is required", ErrInvalidInput)
	}
	if now.IsZero() {
		return res, fmt.Errorf("%w: zero time", ErrInvalidInput)
	}
	if isNil(s.Emitter) && !s.noAudit {
		return res, fmt.Errorf("%w: audit emitter is required", ErrInvalidInput)
	}
	reqs, err := s.Repo.List(ctx, ListFilter{States: []State{StatePending, StateApproved}})
	if err != nil {
		return res, fmt.Errorf("accessrequest: sweep list: %w", err)
	}
	var errs []error
	for _, r := range reqs {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		expired, skipped, err := s.expireOne(ctx, r, now)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			errs = append(errs, fmt.Errorf("accessrequest: sweep %q: %w", r.Id, err))
		case expired:
			res.Expired++
		case skipped:
			res.Skipped++
		}
	}
	return res, errors.Join(errs...)
}

// expireOne applies Expire to r. After a version conflict the request is
// re-read; if it is by then terminal or not due (changed concurrently) it is
// ignored rather than counted.
func (s *Sweeper) expireOne(ctx context.Context, r Request, now time.Time) (bool, bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		next, eerr := Expire(r, now, s.Opts...)
		if eerr != nil {
			return false, false, eerr
		}
		if next.State == r.State {
			return false, false, nil // not due (or changed concurrently)
		}
		if aerr := s.audit(ctx, next, now); aerr != nil {
			return false, false, aerr // audit first: state stays unchanged
		}
		_, uerr := s.Repo.Update(ctx, next)
		if uerr == nil {
			return true, false, nil
		}
		if !errors.Is(uerr, ErrVersionConflict) {
			if errors.Is(uerr, ErrNotFound) {
				return false, false, nil
			}
			return false, false, uerr
		}
		cur, gerr := s.Repo.Get(ctx, r.Id)
		if gerr != nil {
			if errors.Is(gerr, ErrNotFound) {
				return false, false, nil
			}
			return false, false, gerr
		}
		r = cur
	}
	return false, true, nil
}

// errSweepAudit carries no event content.
var errSweepAudit = errors.New("accessrequest: audit event could not be emitted")

// audit emits the expire event for next (the request in its expired state).
// An error or panic from the emitter is reported as errSweepAudit.
func (s *Sweeper) audit(ctx context.Context, next Request, now time.Time) (err error) {
	if isNil(s.Emitter) {
		return nil // only reachable with WithoutAudit
	}
	ev, eerr := NewExpireEvent(next, now)
	if eerr != nil {
		return fmt.Errorf("%w: %w", errSweepAudit, eerr)
	}
	defer func() {
		if recover() != nil {
			err = errSweepAudit
		}
	}()
	if s.Emitter.Emit(ctx, ev) != nil {
		return errSweepAudit
	}
	return nil
}
