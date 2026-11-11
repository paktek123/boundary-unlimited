// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbook

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/hashicorp/boundary/internal/runbook/source"
)

// Repository errors.
var (
	ErrNotFound      = errors.New("runbook: definition not found")
	ErrAlreadyExists = errors.New("runbook: definition already exists")
	// ErrVersionConflict is returned by Update when the stored version differs
	// from the version of the definition being written.
	ErrVersionConflict = errors.New("runbook: version conflict")
	// ErrInvalidInput is returned when a definition fails validation. It wraps
	// the reason, which never contains script content or parameter values.
	ErrInvalidInput = errors.New("runbook: invalid input")
)

// StoredDefinition is the persisted form of a runbook definition, mirroring the
// runbook_definition table. The script body is not stored: only the path, the
// pinned commit and the SHA-256 of the exact bytes, which are verified again
// (source.Verify) before execution.
type StoredDefinition struct {
	Id          string
	ScopeId     string
	Name        string
	Description string
	Interpreter string
	// SourceCommitSHA is the full lowercase 40-hex commit the script is
	// fetched at. Branches, tags and abbreviated SHAs are never stored.
	SourceCommitSHA string
	ScriptPath      string
	ScriptSHA256    string
	Parameters      []Parameter
	Selector        TargetSelector
	// Version is 0 for a definition not yet stored and 1 after Create.
	Version uint32
}

// NewStoredDefinition validates def exactly as the executor will (Compile:
// reserved and duplicate parameter names, undeclared parameters in the script,
// lint) and pins it to the full commit sha and script path. It rejects floating
// refs and short SHAs. The returned definition is ready for Repository.Create.
// Pass WithLintPassMarker only on an explicit, audited override.
func NewStoredDefinition(id, scopeID string, def Definition, sha, scriptPath string, opts ...Option) (StoredDefinition, error) {
	if id == "" || scopeID == "" {
		return StoredDefinition{}, fmt.Errorf("%w: id and scope id are required", ErrInvalidInput)
	}
	if _, err := Compile(def, opts...); err != nil {
		return StoredDefinition{}, fmt.Errorf("%w: %s", ErrInvalidInput, err.Error())
	}
	if err := source.ValidatePath(scriptPath); err != nil {
		return StoredDefinition{}, fmt.Errorf("%w: script path: %s", ErrInvalidInput, err.Error())
	}
	pin, err := source.NewPin(sha, def.Script)
	if err != nil {
		return StoredDefinition{}, fmt.Errorf("%w: commit must be a full 40-hex sha: %s", ErrInvalidInput, err.Error())
	}
	return StoredDefinition{
		Id:              id,
		ScopeId:         scopeID,
		Name:            def.Name,
		Description:     def.Description,
		Interpreter:     def.Interpreter,
		SourceCommitSHA: pin.SHA,
		ScriptPath:      scriptPath,
		ScriptSHA256:    pin.ScriptSHA256,
		Parameters:      append([]Parameter(nil), def.Parameters...),
		Selector:        cloneSelector(def.Selector),
	}, nil
}

// Pin returns the recorded pin, for source.Verify before execution.
func (s StoredDefinition) Pin() source.Pin {
	return source.Pin{SHA: s.SourceCommitSHA, ScriptSHA256: s.ScriptSHA256}
}

// validate re-checks the invariants a stored row must hold. A Repository calls
// it on every write so a hand-built StoredDefinition cannot bypass
// NewStoredDefinition. It cannot re-lint the script (it is not stored).
func (s StoredDefinition) validate() error {
	if s.Id == "" || s.ScopeId == "" {
		return fmt.Errorf("%w: id and scope id are required", ErrInvalidInput)
	}
	if s.Name == "" || len(s.Name) > MaxNameLen || !printable(s.Name) {
		return fmt.Errorf("%w: invalid name", ErrInvalidInput)
	}
	if len(s.Description) > 4096 {
		return fmt.Errorf("%w: invalid description", ErrInvalidInput)
	}
	if _, ok := supportedInterpreters[s.Interpreter]; !ok {
		return fmt.Errorf("%w: unsupported interpreter", ErrInvalidInput)
	}
	if err := source.ValidateSHA(s.SourceCommitSHA); err != nil {
		return fmt.Errorf("%w: commit must be a full 40-hex sha", ErrInvalidInput)
	}
	if err := source.ValidatePath(s.ScriptPath); err != nil {
		return fmt.Errorf("%w: script path: %s", ErrInvalidInput, err.Error())
	}
	if !sha256HexRE.MatchString(s.ScriptSHA256) {
		return fmt.Errorf("%w: script sha256 must be 64 lowercase hex characters", ErrInvalidInput)
	}
	if len(s.Parameters) > MaxParameters {
		return fmt.Errorf("%w: too many parameters", ErrInvalidInput)
	}
	seen := map[string]struct{}{}
	for _, p := range s.Parameters {
		if !paramNameRE.MatchString(p.Name) || IsReservedName(p.Name) {
			return fmt.Errorf("%w: invalid or reserved parameter name %q", ErrInvalidInput, p.Name)
		}
		if _, dup := seen[p.Name]; dup {
			return fmt.Errorf("%w: duplicate parameter %q", ErrInvalidInput, p.Name)
		}
		seen[p.Name] = struct{}{}
		if _, err := compileParam(p); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidInput, err.Error())
		}
	}
	return nil
}

func cloneSelector(s TargetSelector) TargetSelector {
	s.TargetIDs = append([]string(nil), s.TargetIDs...)
	s.ScopeIDs = append([]string(nil), s.ScopeIDs...)
	return s
}

func cloneStored(s StoredDefinition) StoredDefinition {
	s.Parameters = append([]Parameter(nil), s.Parameters...)
	s.Selector = cloneSelector(s.Selector)
	return s
}

// Repository persists runbook definitions. The database-backed implementation
// comes with the API slice; no API, CLI or grant exists yet, so nothing can
// reach a Repository from outside this package's callers.
type Repository interface {
	// Create stores a new definition. Its Version must be zero; the stored
	// definition has Version 1. ErrAlreadyExists if the id or the
	// (scope, name) pair is taken.
	Create(ctx context.Context, d StoredDefinition) (StoredDefinition, error)
	// Get returns the definition or ErrNotFound.
	Get(ctx context.Context, id string) (StoredDefinition, error)
	// List returns the definitions of a scope ordered by name then id.
	List(ctx context.Context, scopeID string) ([]StoredDefinition, error)
	// Update replaces the stored definition only if d.Version equals the stored
	// version, and increments the version. The id and scope are immutable.
	Update(ctx context.Context, d StoredDefinition) (StoredDefinition, error)
	// Delete removes the definition or returns ErrNotFound.
	Delete(ctx context.Context, id string) error
}

// MemRepository is a concurrency-safe in-memory Repository for tests. It
// applies the same write validation a database-backed Repository must.
type MemRepository struct {
	mu   sync.Mutex
	defs map[string]StoredDefinition
}

// NewMemRepository returns an empty MemRepository.
func NewMemRepository() *MemRepository {
	return &MemRepository{defs: map[string]StoredDefinition{}}
}

var _ Repository = (*MemRepository)(nil)

func (m *MemRepository) nameTaken(d StoredDefinition) bool {
	for _, o := range m.defs {
		if o.ScopeId == d.ScopeId && o.Name == d.Name && o.Id != d.Id {
			return true
		}
	}
	return false
}

// Create implements Repository.
func (m *MemRepository) Create(ctx context.Context, d StoredDefinition) (StoredDefinition, error) {
	if err := ctx.Err(); err != nil {
		return StoredDefinition{}, err
	}
	if d.Version != 0 {
		return StoredDefinition{}, fmt.Errorf("%w: version must be zero", ErrInvalidInput)
	}
	if err := d.validate(); err != nil {
		return StoredDefinition{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.defs[d.Id]; ok || m.nameTaken(d) {
		return StoredDefinition{}, ErrAlreadyExists
	}
	d = cloneStored(d)
	d.Version = 1
	m.defs[d.Id] = d
	return cloneStored(d), nil
}

// Get implements Repository.
func (m *MemRepository) Get(ctx context.Context, id string) (StoredDefinition, error) {
	if err := ctx.Err(); err != nil {
		return StoredDefinition{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.defs[id]
	if !ok {
		return StoredDefinition{}, ErrNotFound
	}
	return cloneStored(d), nil
}

// List implements Repository.
func (m *MemRepository) List(ctx context.Context, scopeID string) ([]StoredDefinition, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []StoredDefinition
	for _, d := range m.defs {
		if d.ScopeId == scopeID {
			out = append(out, cloneStored(d))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Id < out[j].Id
	})
	return out, nil
}

// Update implements Repository.
func (m *MemRepository) Update(ctx context.Context, d StoredDefinition) (StoredDefinition, error) {
	if err := ctx.Err(); err != nil {
		return StoredDefinition{}, err
	}
	if err := d.validate(); err != nil {
		return StoredDefinition{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.defs[d.Id]
	if !ok {
		return StoredDefinition{}, ErrNotFound
	}
	if cur.ScopeId != d.ScopeId {
		return StoredDefinition{}, fmt.Errorf("%w: scope id is immutable", ErrInvalidInput)
	}
	if cur.Version != d.Version {
		return StoredDefinition{}, ErrVersionConflict
	}
	if m.nameTaken(d) {
		return StoredDefinition{}, ErrAlreadyExists
	}
	d = cloneStored(d)
	d.Version = cur.Version + 1
	m.defs[d.Id] = d
	return cloneStored(d), nil
}

// Delete implements Repository.
func (m *MemRepository) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.defs[id]; !ok {
		return ErrNotFound
	}
	delete(m.defs, id)
	return nil
}
