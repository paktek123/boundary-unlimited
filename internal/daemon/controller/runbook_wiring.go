// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package controller

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/runbooks"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/runbook"
	runbookdb "github.com/hashicorp/boundary/internal/runbook/db"
)

// runbookSysEmitter publishes runbook write audit events as controller system
// events. It forwards only identifiers, the operation, the version and the
// timestamp (runbooks.WriteEvent has no script or free-text field).
type runbookSysEmitter struct {
	write func(ctx context.Context, op event.Op, msg string, args ...any)
}

var _ runbooks.Emitter = runbookSysEmitter{}

// Emit implements runbooks.Emitter. A missing writer is an error so that a
// write is never applied without an audit event.
func (e runbookSysEmitter) Emit(ctx context.Context, ev runbooks.WriteEvent) error {
	if e.write == nil {
		return errors.New("controller: runbook emitter has no writer")
	}
	e.write(ctx, "controller.runbookAudit", ev.Op,
		"runbook_id", ev.RunbookId,
		"scope_id", ev.ScopeId,
		"principal_id", ev.PrincipalId,
		"version", ev.Version,
		"at", ev.Timestamp.UTC().Format(time.RFC3339),
	)
	return nil
}

// runbookReadDelete exposes only GetRunbook, ListRunbooks and DeleteRunbook of
// the adapter. CreateRunbook and UpdateRunbook are deliberately not served
// (they stay Unimplemented) until the pin-only create/update slice (#321) is
// enabled; embedding the Unimplemented server guarantees that.
type runbookReadDelete struct {
	pbs.UnimplementedRunbookServiceServer
	inner *runbooks.GRPCService
}

func (r runbookReadDelete) GetRunbook(ctx context.Context, req *pbs.GetRunbookRequest) (*pbs.GetRunbookResponse, error) {
	return r.inner.GetRunbook(ctx, req)
}

func (r runbookReadDelete) ListRunbooks(ctx context.Context, req *pbs.ListRunbooksRequest) (*pbs.ListRunbooksResponse, error) {
	return r.inner.ListRunbooks(ctx, req)
}

func (r runbookReadDelete) DeleteRunbook(ctx context.Context, req *pbs.DeleteRunbookRequest) (*pbs.DeleteRunbookResponse, error) {
	return r.inner.DeleteRunbook(ctx, req)
}

// newRunbookServer builds the get/list/delete-only runbook server. It returns
// nil when any dependency is missing (fail closed: the API is not registered).
func newRunbookServer(repo runbook.Repository, emit runbooks.Emitter, callers runbooks.CallerResolver) pbs.RunbookServiceServer {
	if repo == nil || emit == nil || callers == nil {
		return nil
	}
	svc, err := runbooks.NewService(repo, emit)
	if err != nil {
		return nil
	}
	g, err := runbooks.NewGRPCService(svc, callers)
	if err != nil {
		return nil
	}
	return runbookReadDelete{inner: g}
}

// buildRunbookServer builds the DB-backed server. A failure is reported as a
// system event with a fixed reason and leaves the API unregistered.
func buildRunbookServer(ctx context.Context, rw *db.Db, k *kms.Kms) pbs.RunbookServiceServer {
	const op = "controller.buildRunbookServer"
	repo, err := runbookdb.NewRepository(ctx, rw, rw, k)
	if err != nil {
		event.WriteSysEvent(ctx, op, "runbook API not registered", "reason", "repository could not be built")
		return nil
	}
	srv := newRunbookServer(repo, runbookSysEmitter{write: event.WriteSysEvent}, runbooks.NewVerifiedCallerResolver())
	if srv == nil {
		event.WriteSysEvent(ctx, op, "runbook API not registered", "reason", "service could not be built")
	}
	return srv
}
