// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package accessrequest

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Sweeper expires pending requests past their maximum age and approved
// requests past ExpiresAt. It is safe to run repeatedly and concurrently.
type Sweeper struct {
	Repo Repository
	Opts []Option
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

func (s *Sweeper) expireOne(ctx context.Context, r Request, now time.Time) (expired, skipped bool, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		next, err := Expire(r, now, s.Opts...)
		if err != nil {
			return false, false, err
		}
		if next.State == r.State {
			return false, false, nil // not due (or changed concurrently)
		}
		_, err = s.Repo.Update(ctx, next)
		if err == nil {
			return true, false, nil
		}
		if !errors.Is(err, ErrVersionConflict) {
			if errors.Is(err, ErrNotFound) {
				return false, false, nil
			}
			return false, false, err
		}
		if r, err = s.Repo.Get(ctx, r.Id); err != nil {
			if errors.Is(err, ErrNotFound) {
				return false, false, nil
			}
			return false, false, err
		}
	}
	return false, true, nil
}
