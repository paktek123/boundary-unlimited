// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"errors"
)

// Repository errors.
var (
	ErrNotFound      = errors.New("accessrequest: request not found")
	ErrAlreadyExists = errors.New("accessrequest: request already exists")
	// ErrVersionConflict is returned by Update when the stored version differs
	// from the version of the request being written.
	ErrVersionConflict = errors.New("accessrequest: version conflict")
)

// ListFilter selects requests. Zero fields match everything. States, when
// non-empty, matches any of them.
type ListFilter struct {
	// ScopeId, when set, restricts the result to requests of that scope.
	ScopeId     string
	RequesterId string
	// ApproverId matches requests decided by this user (DecidedBy).
	ApproverId string
	States     []State
}

// Repository persists requests. The database-backed implementation comes later;
// this is the interface it will implement.
type Repository interface {
	// Create stores a new request. Its Version must be zero; the stored
	// request has Version 1. ErrAlreadyExists if the id is taken.
	Create(ctx context.Context, r Request) (Request, error)
	// Get returns the request or ErrNotFound.
	Get(ctx context.Context, id string) (Request, error)
	// List returns matching requests ordered by CreatedAt then Id.
	List(ctx context.Context, f ListFilter) ([]Request, error)
	// Update replaces the stored request only if r.Version equals the stored
	// version, and increments the version. ErrVersionConflict otherwise.
	Update(ctx context.Context, r Request) (Request, error)
}

// ActiveLister is implemented by repositories that can return the requests
// that are currently granting access. Both MemRepository and DBRepository
// implement it; each compares times against one injected clock.
type ActiveLister interface {
	// ListActive returns the requests matching f that are approved and not
	// yet expired according to the repository's clock. A request is expired
	// when now >= ExpiresAt, so the expiry instant itself is expired. Pending,
	// denied, cancelled, expired and revoked requests are never returned,
	// whatever f.States says.
	ListActive(ctx context.Context, f ListFilter) ([]Request, error)
}
