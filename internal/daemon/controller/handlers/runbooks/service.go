// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package runbooks implements the runbook definition service
// (create/get/list/update/delete) over runbook.Repository. It is NOT
// registered in the controller: only the in-memory repository exists, so
// nothing outside tests can reach it. Run/execute always returns
// ErrRunNotSupported until the executor is wired.
package runbooks

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/runbook"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// Errors returned by the service. None carries script bodies or caller input.
var (
	ErrForbidden       = errors.New("runbooks: forbidden")
	ErrNotFound        = errors.New("runbooks: not found")
	ErrInvalid         = errors.New("runbooks: invalid request")
	ErrConflict        = errors.New("runbooks: conflict")
	ErrRunNotSupported = errors.New("runbooks: running a runbook is not yet supported")
)

// Caller is the authenticated principal and its resolved grants.
type Caller struct {
	UserId string
	ACL    perms.ACL
}

// WriteEvent is the audit event for a definition write. It holds ids and the
// operation only: never a script body, parameter or description.
type WriteEvent struct {
	Op          string // create, update or delete
	RunbookId   string
	ScopeId     string
	PrincipalId string
	Version     uint32
	Timestamp   time.Time
	// CommitSHA and ParamNames are set for pin-only writes (never values).
	CommitSHA  string
	ParamNames []string
}

// Emitter publishes write audit events. A failure fails the write closed
// when it happens before the change is applied; see each method.
type Emitter interface {
	Emit(ctx context.Context, e WriteEvent) error
}

// Request carries a definition and its pin.
type Request struct {
	ScopeId    string
	Definition runbook.Definition
	// CommitSHA is the full 40-hex commit; branches, tags and short SHAs are rejected.
	CommitSHA  string
	ScriptPath string
	// Version is required for Update (optimistic concurrency).
	Version uint32
}

// Service implements the definition operations.
type Service struct {
	repo  runbook.Repository
	emit  Emitter
	now   func() time.Time
	newId func(context.Context) (string, error)
}

// Option configures a Service.
type Option func(*Service)

// WithClock sets the clock (tests).
func WithClock(f func() time.Time) Option { return func(s *Service) { s.now = f } }

// WithIdGenerator sets the id generator (tests).
func WithIdGenerator(f func(context.Context) (string, error)) Option {
	return func(s *Service) { s.newId = f }
}

// NewService builds a Service. The repository and emitter are required.
func NewService(repo runbook.Repository, emit Emitter, opt ...Option) (*Service, error) {
	if repo == nil || emit == nil {
		return nil, fmt.Errorf("%w: repository and emitter are required", ErrInvalid)
	}
	s := &Service{
		repo: repo, emit: emit, now: time.Now,
		newId: func(ctx context.Context) (string, error) { return db.NewPublicId(ctx, "rb") },
	}
	for _, o := range opt {
		o(s)
	}
	return s, nil
}

func (s *Service) allowed(c Caller, scopeId, id string, a action.Type) bool {
	if c.UserId == "" || scopeId == "" {
		return false
	}
	return c.ACL.Allowed(perms.Resource{ScopeId: scopeId, Id: id, Type: resource.Runbook}, a, c.UserId).Authorized
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, runbook.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, runbook.ErrAlreadyExists), errors.Is(err, runbook.ErrVersionConflict):
		return ErrConflict
	case errors.Is(err, runbook.ErrInvalidInput):
		// The repository error text never carries script content.
		return fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	default:
		return errors.New("runbooks: internal error")
	}
}

func (s *Service) audit(ctx context.Context, op string, d runbook.StoredDefinition, c Caller) error {
	return s.emit.Emit(ctx, WriteEvent{Op: op, RunbookId: d.Id, ScopeId: d.ScopeId, PrincipalId: c.UserId, Version: d.Version, Timestamp: s.now()})
}

// Create validates and stores a definition.
func (s *Service) Create(ctx context.Context, c Caller, r Request) (runbook.StoredDefinition, error) {
	if !s.allowed(c, r.ScopeId, "", action.Create) {
		return runbook.StoredDefinition{}, ErrForbidden
	}
	id, err := s.newId(ctx)
	if err != nil {
		return runbook.StoredDefinition{}, errors.New("runbooks: internal error")
	}
	d, err := runbook.NewStoredDefinition(id, r.ScopeId, r.Definition, r.CommitSHA, r.ScriptPath)
	if err != nil {
		return runbook.StoredDefinition{}, mapErr(err)
	}
	out, err := s.repo.Create(ctx, d)
	if err != nil {
		return runbook.StoredDefinition{}, mapErr(err)
	}
	if err := s.audit(ctx, "create", out, c); err != nil {
		// Fail closed: do not keep a write that could not be audited.
		_ = s.repo.Delete(ctx, out.Id)
		return runbook.StoredDefinition{}, errors.New("runbooks: audit failed")
	}
	return out, nil
}

// Get returns a definition. A missing id and a definition the caller may not
// read both return ErrForbidden, so existence is not leaked; ErrNotFound is
// never returned here.
func (s *Service) Get(ctx context.Context, c Caller, id string) (runbook.StoredDefinition, error) {
	d, err := s.repo.Get(ctx, id)
	if err != nil {
		if errors.Is(err, runbook.ErrNotFound) {
			return runbook.StoredDefinition{}, ErrForbidden
		}
		return runbook.StoredDefinition{}, mapErr(err)
	}
	if !s.allowed(c, d.ScopeId, d.Id, action.Read) {
		return runbook.StoredDefinition{}, ErrForbidden
	}
	return d, nil
}

// List returns the definitions of a scope the caller may list, filtered to
// those the caller may read.
func (s *Service) List(ctx context.Context, c Caller, scopeId string) ([]runbook.StoredDefinition, error) {
	if !s.allowed(c, scopeId, "", action.List) {
		return nil, ErrForbidden
	}
	all, err := s.repo.List(ctx, scopeId)
	if err != nil {
		return nil, mapErr(err)
	}
	var out []runbook.StoredDefinition
	for _, d := range all {
		if d.ScopeId == scopeId && s.allowed(c, d.ScopeId, d.Id, action.Read) {
			out = append(out, d)
		}
	}
	return out, nil
}

// Update replaces a definition if r.Version matches the stored version.
func (s *Service) Update(ctx context.Context, c Caller, id string, r Request) (runbook.StoredDefinition, error) {
	cur, err := s.repo.Get(ctx, id)
	if err != nil {
		if errors.Is(err, runbook.ErrNotFound) {
			return runbook.StoredDefinition{}, ErrForbidden
		}
		return runbook.StoredDefinition{}, mapErr(err)
	}
	if !s.allowed(c, cur.ScopeId, cur.Id, action.Update) {
		return runbook.StoredDefinition{}, ErrForbidden
	}
	d, err := runbook.NewStoredDefinition(cur.Id, cur.ScopeId, r.Definition, r.CommitSHA, r.ScriptPath)
	if err != nil {
		return runbook.StoredDefinition{}, mapErr(err)
	}
	d.Version = r.Version
	out, err := s.repo.Update(ctx, d)
	if err != nil {
		return runbook.StoredDefinition{}, mapErr(err)
	}
	if err := s.audit(ctx, "update", out, c); err != nil {
		// Best-effort revert: the content is restored but the repository bumps
		// the version again (cur.Version+2), so a client retrying with the
		// version it read gets ErrConflict. The revert error is discarded; if
		// it fails an unaudited change persists. A transactional DB-backed
		// repository must replace this (follow-up on the DB repository slice).
		_, _ = s.repo.Update(ctx, withVersion(cur, out.Version))
		return runbook.StoredDefinition{}, errors.New("runbooks: audit failed")
	}
	return out, nil
}

func withVersion(d runbook.StoredDefinition, v uint32) runbook.StoredDefinition {
	d.Version = v
	return d
}

// Delete removes a definition. The audit event is emitted first; if it
// fails the definition is kept (fail closed). If the delete itself then fails
// (for example a concurrent delete) the event records a delete that did not
// happen; that is accepted in favour of failing closed.
func (s *Service) Delete(ctx context.Context, c Caller, id string) error {
	cur, err := s.repo.Get(ctx, id)
	if err != nil {
		if errors.Is(err, runbook.ErrNotFound) {
			return ErrForbidden
		}
		return mapErr(err)
	}
	if !s.allowed(c, cur.ScopeId, cur.Id, action.Delete) {
		return ErrForbidden
	}
	if err := s.audit(ctx, "delete", cur, c); err != nil {
		return errors.New("runbooks: audit failed")
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return mapErr(err)
	}
	return nil
}

// Run always returns ErrRunNotSupported, whoever asks and whatever the id.
func (s *Service) Run(_ context.Context, _ Caller, _ string) error {
	return ErrRunNotSupported
}

// PinnedRequest carries a definition as a reference only: the pinned commit
// and script path plus metadata. There is no script field.
type PinnedRequest struct {
	ScopeId     string
	Name        string
	Description string
	Interpreter string
	Parameters  []runbook.Parameter
	Selector    runbook.TargetSelector
	CommitSHA   string
	ScriptPath  string
	// Version is required for UpdatePinned.
	Version uint32
}

func (s *Service) auditPinned(ctx context.Context, op string, d runbook.StoredDefinition, c Caller) error {
	names := make([]string, 0, len(d.Parameters))
	for _, p := range d.Parameters {
		names = append(names, p.Name)
	}
	return s.emit.Emit(ctx, WriteEvent{Op: op, RunbookId: d.Id, ScopeId: d.ScopeId, PrincipalId: c.UserId,
		Version: d.Version, Timestamp: s.now(), CommitSHA: d.SourceCommitSHA, ParamNames: names})
}

// CreatePinned stores an unverified definition from a pin reference. It never
// fetches anything; the result is refused by run and approval binding until a
// verified script hash exists.
func (s *Service) CreatePinned(ctx context.Context, c Caller, r PinnedRequest) (runbook.StoredDefinition, error) {
	if !s.allowed(c, r.ScopeId, "", action.Create) {
		return runbook.StoredDefinition{}, ErrForbidden
	}
	id, err := s.newId(ctx)
	if err != nil {
		return runbook.StoredDefinition{}, errors.New("runbooks: internal error")
	}
	d, err := runbook.NewUnverifiedStoredDefinition(id, r.ScopeId, r.Name, r.Description, r.Interpreter, r.Parameters, r.Selector, r.CommitSHA, r.ScriptPath)
	if err != nil {
		return runbook.StoredDefinition{}, mapErr(err)
	}
	out, err := s.repo.Create(ctx, d)
	if err != nil {
		return runbook.StoredDefinition{}, mapErr(err)
	}
	if err := s.auditPinned(ctx, "create", out, c); err != nil {
		_ = s.repo.Delete(ctx, out.Id)
		return runbook.StoredDefinition{}, errors.New("runbooks: audit failed")
	}
	return out, nil
}

// UpdatePinned replaces a definition's metadata and pin if r.Version matches.
// Changing the commit or script path resets the definition to unverified.
func (s *Service) UpdatePinned(ctx context.Context, c Caller, id string, r PinnedRequest) (runbook.StoredDefinition, error) {
	if r.Version == 0 {
		return runbook.StoredDefinition{}, fmt.Errorf("%w: version is required", ErrInvalid)
	}
	cur, err := s.repo.Get(ctx, id)
	if err != nil {
		if errors.Is(err, runbook.ErrNotFound) {
			return runbook.StoredDefinition{}, ErrForbidden
		}
		return runbook.StoredDefinition{}, mapErr(err)
	}
	if !s.allowed(c, cur.ScopeId, cur.Id, action.Update) {
		return runbook.StoredDefinition{}, ErrForbidden
	}
	d, err := runbook.NewUnverifiedStoredDefinition(cur.Id, cur.ScopeId, r.Name, r.Description, r.Interpreter, r.Parameters, r.Selector, r.CommitSHA, r.ScriptPath)
	if err != nil {
		return runbook.StoredDefinition{}, mapErr(err)
	}
	if r.CommitSHA == cur.SourceCommitSHA && r.ScriptPath == cur.ScriptPath {
		d.ScriptSHA256 = cur.ScriptSHA256 // same pin: verification is kept
	}
	d.Version = r.Version
	out, err := s.repo.Update(ctx, d)
	if err != nil {
		return runbook.StoredDefinition{}, mapErr(err)
	}
	if err := s.auditPinned(ctx, "update", out, c); err != nil {
		_, _ = s.repo.Update(ctx, withVersion(cur, out.Version))
		return runbook.StoredDefinition{}, errors.New("runbooks: audit failed")
	}
	return out, nil
}
