// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package accessrequest

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// MemRepository is a concurrency-safe in-memory Repository for tests.
type MemRepository struct {
	mu   sync.Mutex
	reqs map[string]Request
}

// NewMemRepository returns an empty MemRepository.
func NewMemRepository() *MemRepository {
	return &MemRepository{reqs: map[string]Request{}}
}

var _ Repository = (*MemRepository)(nil)

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
