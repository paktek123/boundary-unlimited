// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package run

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/runbook"
	"github.com/hashicorp/boundary/internal/runbook/approval"
	"github.com/hashicorp/boundary/internal/runbook/source"
)

// Errors returned by Run. None contains a parameter value or script text.
var (
	ErrInvalidRequest = errors.New("run: invalid request")
	ErrNotPermitted   = errors.New("run: target is not selected by the runbook")
	ErrAudit          = errors.New("run: audit event could not be emitted")
	ErrExecute        = errors.New("run: execution failed")
	ErrFetch          = errors.New("run: could not fetch the pinned script")
	ErrInternal       = errors.New("run: internal error")
)

// RenderedBinding is everything an Executor receives: the rendered
// invocation (which carries the parameter values it needs to run), the
// approved binding it was checked against and the target to run on.
type RenderedBinding struct {
	Invocation  *runbook.Invocation
	Binding     approval.Binding
	TargetID    string
	PrincipalID string
}

// String lists names only; it never prints values.
func (r RenderedBinding) String() string {
	return fmt.Sprintf("run.RenderedBinding{binding=%s target=%q}", r.Binding, r.TargetID)
}
func (r RenderedBinding) GoString() string           { return r.String() }
func (r RenderedBinding) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(r.String())) }

// Result is what an Executor reports. It carries no output text.
type Result struct {
	ExitCode  int
	SessionID string
}

// Executor runs a fully verified invocation.
type Executor interface {
	Execute(ctx context.Context, rb RenderedBinding) (Result, error)
}

// Request describes one run.
type Request struct {
	// Def provides name, selector, interpreter and parameters. Its Script is
	// ignored: the script always comes from the pinned fetch.
	Def runbook.Definition
	// RepoURL, Path and SHA locate the script; SHA must be a full commit SHA.
	RepoURL, Path, SHA string
	// Limits bounds the fetch.
	Limits source.Limits
	// Params are the caller supplied parameter values.
	Params map[string]string
	// Approved is the binding that was approved; it must match exactly.
	Approved approval.Binding
	// RunbookID, PrincipalID, TargetID and TargetScopeID identify the run.
	RunbookID, PrincipalID, TargetID, TargetScopeID string
	// LintPassMarker is the caller's explicit lint override (see
	// runbook.WithLintPassMarker).
	LintPassMarker bool
}

// Runner performs runs. All fields are required.
type Runner struct {
	Fetcher  source.Fetcher
	Emitter  runbook.Emitter
	Executor Executor
	// Now returns the event time; nil uses time.Now.
	Now func() time.Time
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// Run executes req. It never calls the Executor unless every check passed and
// the start audit event was emitted. A failed check emits a best-effort
// rejection event and returns the failure. The finish event carries names
// only; an error emitting it is returned alongside the Executor's Result.
// A nil error does not mean the script succeeded: callers must also check
// Result.ExitCode (non-zero is recorded as a failure outcome). An Executor
// panic is recovered, recorded as a failure outcome and returned as ErrExecute.
// The finish event is emitted even if ctx was cancelled while the Executor ran.
func (r *Runner) Run(ctx context.Context, req Request) (res Result, err error) {
	defer func() {
		if recover() != nil {
			res, err = Result{}, ErrInternal
		}
	}()
	if r == nil || r.Fetcher == nil || r.Emitter == nil || r.Executor == nil {
		return Result{}, fmt.Errorf("%w: runner not configured", ErrInvalidRequest)
	}
	// reject emits a best-effort rejection event. If the failure was itself an
	// audit failure there is nothing to add: no further event is attempted.
	reject := func(err error) (Result, error) {
		r.rejected(ctx, req)
		return Result{}, err
	}

	script, pin, err := source.Get(ctx, r.Fetcher, req.RepoURL, req.SHA, req.Path, req.Limits)
	if err != nil {
		switch {
		case errors.Is(err, source.ErrInvalidRef), errors.Is(err, source.ErrInvalidPath):
		default:
			err = ErrFetch // fetcher errors can carry URLs or tokens; never propagated
		}
		return reject(err)
	}
	// Re-verify the fetched bytes against the approved script hash.
	if err := source.Verify(source.Pin{SHA: req.SHA, ScriptSHA256: req.Approved.ScriptHash}, script); err != nil {
		return reject(err)
	}
	def := req.Def
	def.Script = script
	var opts []runbook.Option
	if req.LintPassMarker {
		opts = append(opts, runbook.WithLintPassMarker())
	}
	compiled, err := runbook.Compile(def, opts...)
	if err != nil {
		return reject(err)
	}
	vals, err := compiled.Validate(req.Params)
	if err != nil {
		return reject(err)
	}
	if !selected(compiled.Selector(), req.TargetID, req.TargetScopeID) {
		return reject(ErrNotPermitted)
	}
	current, err := approval.Bind(def, pin)
	if err != nil {
		return reject(err)
	}
	if err := approval.Verify(req.Approved, current); err != nil {
		return reject(err)
	}
	inv, err := runbook.Render(compiled, vals)
	if err != nil {
		return reject(err)
	}

	in := runbook.EventInput{
		Type: runbook.EventRunStarted, RunbookId: req.RunbookID, CommitSHA: pin.SHA, ScriptSHA256: pin.ScriptSHA256,
		Params: vals, PrincipalId: req.PrincipalID, TargetId: req.TargetID,
		Timestamp: r.now(), LintPassMarker: compiled.LintMarkerUsed(),
	}
	if err := r.emit(ctx, in); err != nil { // start event precedes the Executor call
		return Result{}, err
	}

	res, execErr := r.execute(ctx, RenderedBinding{Invocation: inv, Binding: current, TargetID: req.TargetID, PrincipalID: req.PrincipalID})
	in.Type, in.Timestamp, in.Outcome, in.SessionId = runbook.EventRunFinished, r.now(), runbook.OutcomeSuccess, res.SessionID
	if execErr != nil || res.ExitCode != 0 {
		in.Outcome = runbook.OutcomeFailure
	}
	// The run happened, so its end must be audited even if ctx was cancelled.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishEmitTimeout)
	defer cancel()
	if emitErr := r.emit(fctx, in); emitErr != nil {
		return res, emitErr
	}
	if execErr != nil {
		return res, ErrExecute // the Executor's error text is not propagated
	}
	return res, nil
}

// finishEmitTimeout bounds the finish event emission.
const finishEmitTimeout = 5 * time.Second

// execute calls the Executor and turns a panic into an error so the finish
// event is still emitted. The panic value is never propagated.
func (r *Runner) execute(ctx context.Context, rb RenderedBinding) (res Result, err error) {
	defer func() {
		if recover() != nil {
			res, err = Result{}, ErrExecute
		}
	}()
	return r.Executor.Execute(ctx, rb)
}

func (r *Runner) emit(ctx context.Context, in runbook.EventInput) error {
	ev, err := runbook.NewEvent(in)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAudit, err)
	}
	if err := r.Emitter.Emit(ctx, ev); err != nil {
		return ErrAudit
	}
	return nil
}

// rejected emits a best-effort rejection event built from the approved
// binding. Failure to build or emit it never changes the returned error.
func (r *Runner) rejected(ctx context.Context, req Request) {
	ev, err := runbook.NewEvent(runbook.EventInput{
		Type: runbook.EventRunRejected, RunbookId: req.RunbookID, CommitSHA: req.Approved.CommitSHA,
		ScriptSHA256: req.Approved.ScriptHash, PrincipalId: req.PrincipalID, TargetId: req.TargetID,
		Outcome: runbook.OutcomeRejected, Timestamp: r.now(),
	})
	if err == nil {
		_ = r.Emitter.Emit(ctx, ev)
	}
}

func selected(s runbook.TargetSelector, targetID, scopeID string) bool {
	if targetID == "" {
		return false
	}
	if s.AllTargets {
		return true
	}
	for _, id := range s.TargetIDs {
		if id == targetID {
			return true
		}
	}
	if scopeID != "" {
		for _, id := range s.ScopeIDs {
			if id == scopeID {
				return true
			}
		}
	}
	return false
}
