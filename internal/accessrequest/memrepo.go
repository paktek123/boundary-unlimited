// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MemRepository is a concurrency-safe in-memory Repository for tests. It is
// deliberately permissive: Create accepts a request in any state and Update
// does not check that the state change is a valid transition. Callers must use
// the state-machine functions, and a database-backed Repository must not
// inherit this gap silently: it should validate both.
type MemRepository struct {
	mu    sync.Mutex
	reqs  map[string]Request
	clock func() time.Time
}

// NewMemRepository returns an empty MemRepository.
func NewMemRepository() *MemRepository {
	return &MemRepository{reqs: map[string]Request{}}
}

// NewMemRepositoryWithClock returns an empty MemRepository whose ListActive
// uses clock as its only source of time. A nil clock means time.Now.
func NewMemRepositoryWithClock(clock func() time.Time) *MemRepository {
	m := NewMemRepository()
	m.clock = clock
	return m
}

var (
	_ Repository   = (*MemRepository)(nil)
	_ ActiveLister = (*MemRepository)(nil)
)

func clone(r Request) Request {
	r.Grants = append([]string(nil), r.Grants...)
	return r
}

// Create implements Repository.
func (m *MemRepository) Create(ctx context.Context, r Request) (Request, error) {
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	if r.Id == "" || r.Version != 0 {
		return Request{}, fmt.Errorf("%w: id required and version must be zero", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.reqs[r.Id]; ok {
		return Request{}, ErrAlreadyExists
	}
	r = clone(r)
	r.Version = 1
	m.reqs[r.Id] = r
	return clone(r), nil
}

// Get implements Repository.
func (m *MemRepository) Get(ctx context.Context, id string) (Request, error) {
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok {
		return Request{}, ErrNotFound
	}
	return clone(r), nil
}

// List implements Repository.
func (m *MemRepository) List(ctx context.Context, f ListFilter) ([]Request, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Request
	for _, r := range m.reqs {
		if f.ScopeId != "" && r.ScopeId != f.ScopeId {
			continue
		}
		if f.RequesterId != "" && r.RequesterId != f.RequesterId {
			continue
		}
		if f.ApproverId != "" && r.DecidedBy != f.ApproverId {
			continue
		}
		if len(f.States) > 0 {
			match := false
			for _, s := range f.States {
				if r.State == s {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		out = append(out, clone(r))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Id < out[j].Id
	})
	return out, nil
}

// Update implements Repository.
func (m *MemRepository) Update(ctx context.Context, r Request) (Request, error) {
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.reqs[r.Id]
	if !ok {
		return Request{}, ErrNotFound
	}
	if cur.Version != r.Version {
		return Request{}, ErrVersionConflict
	}
	r = clone(r)
	r.Version = cur.Version + 1
	m.reqs[r.Id] = r
	return clone(r), nil
}

// ListActive implements ActiveLister.
func (m *MemRepository) ListActive(ctx context.Context, f ListFilter) ([]Request, error) {
	now := time.Now()
	if m.clock != nil {
		now = m.clock()
	}
	f.States = intersectApproved(f.States)
	if f.States == nil {
		return nil, ctx.Err()
	}
	all, err := m.List(ctx, f)
	if err != nil {
		return nil, err
	}
	var out []Request
	for _, r := range all {
		if isActive(r, now) {
			out = append(out, r)
		}
	}
	return out, nil
}

// intersectApproved narrows a state filter to approved only. It returns nil
// when the filter excludes approved.
func intersectApproved(states []State) []State {
	if len(states) == 0 {
		return []State{StateApproved}
	}
	for _, s := range states {
		if s == StateApproved {
			return []State{StateApproved}
		}
	}
	return nil
}

// isActive reports whether r is approved with an expiry strictly after now.
func isActive(r Request, now time.Time) bool {
	return r.State == StateApproved && !r.ExpiresAt.IsZero() && now.Before(r.ExpiresAt)
}
