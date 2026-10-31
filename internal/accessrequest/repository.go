// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

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
