// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package controller

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/runbooks"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/runbook"
	runbookdb "github.com/hashicorp/boundary/internal/runbook/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	resp, err := r.inner.GetRunbook(ctx, req)
	return resp, toAPIStatusErr(err)
}

func (r runbookReadDelete) ListRunbooks(ctx context.Context, req *pbs.ListRunbooksRequest) (*pbs.ListRunbooksResponse, error) {
	resp, err := r.inner.ListRunbooks(ctx, req)
	return resp, toAPIStatusErr(err)
}

func (r runbookReadDelete) DeleteRunbook(ctx context.Context, req *pbs.DeleteRunbookRequest) (*pbs.DeleteRunbookResponse, error) {
	resp, err := r.inner.DeleteRunbook(ctx, req)
	return resp, toAPIStatusErr(err)
}

// apiStatusErr carries both a *handlers.ApiError, which the controller's
// errorInterceptor and the HTTP gateway turn into the right HTTP status, and
// the original gRPC status, so gRPC clients still see the same code.
type apiStatusErr struct {
	api *handlers.ApiError
	st  *status.Status
}

func (e apiStatusErr) Error() string              { return e.api.Error() }
func (e apiStatusErr) Unwrap() error              { return e.api }
func (e apiStatusErr) GRPCStatus() *status.Status { return e.st }

// toAPIStatusErr converts the gRPC status errors returned by the runbooks
// adapter into API errors. Without it the HTTP gateway reports every failure,
// including "unauthenticated" and "forbidden", as HTTP 500. The messages are
// the adapter's fixed strings, never request data.
// The default branch below forwards st.Message(); that is safe only because
// the adapter's messages are fixed strings, so keep it that way.
func toAPIStatusErr(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		st = status.New(codes.Internal, "internal error")
	}
	var base error
	switch st.Code() {
	case codes.Unauthenticated:
		base = handlers.UnauthenticatedError()
	case codes.PermissionDenied:
		base = handlers.ForbiddenError()
	default:
		base = handlers.ApiErrorWithCodeAndMessage(st.Code(), "%s", st.Message())
	}
	var api *handlers.ApiError
	if !errors.As(base, &api) {
		return err
	}
	return apiStatusErr{api: api, st: st}
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
