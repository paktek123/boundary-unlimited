// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/runbooks"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/runbook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type noEmit struct{}

func (noEmit) Emit(context.Context, runbooks.WriteEvent) error { return nil }

type noCaller struct{}

func (noCaller) Caller(context.Context) (runbooks.Caller, error) {
	return runbooks.Caller{}, errors.New("unauthenticated")
}

func TestNewRunbookServer_FailClosed(t *testing.T) {
	// Every missing dependency leaves the API unregistered (nil server).
	assert.Nil(t, newRunbookServer(nil, noEmit{}, noCaller{}))
	assert.Nil(t, newRunbookServer(nil, nil, nil))
}

func TestRunbookSysEmitter(t *testing.T) {
	ctx := context.Background()
	require.Error(t, runbookSysEmitter{}.Emit(ctx, runbooks.WriteEvent{}))

	var got []any
	e := runbookSysEmitter{write: func(_ context.Context, _ event.Op, _ string, args ...any) { got = args }}
	require.NoError(t, e.Emit(ctx, runbooks.WriteEvent{Op: "delete", RunbookId: "rb_1", ScopeId: "global", PrincipalId: "u_1", Timestamp: time.Unix(0, 0)}))
	assert.Contains(t, got, "runbook_id")
	// no script, parameter or description key is ever forwarded
	assert.NotContains(t, got, "script")
	assert.NotContains(t, got, "description")
}

func TestRunbookReadDelete_CreateUpdateUnimplemented(t *testing.T) {
	ctx := context.Background()
	s := runbookReadDelete{}
	_, err := s.CreateRunbook(ctx, &pbs.CreateRunbookRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = s.UpdateRunbook(ctx, &pbs.UpdateRunbookRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

type userNoGrants struct{}

func (userNoGrants) Caller(context.Context) (runbooks.Caller, error) {
	return runbooks.Caller{UserId: "u_1234567890"}, nil
}

func TestNewRunbookServer_ServedRPCsRefuseWithoutAuthOrGrant(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		callers runbooks.CallerResolver
		want    codes.Code
	}{
		"unauthenticated": {noCaller{}, codes.Unauthenticated},
		"no grants":       {userNoGrants{}, codes.PermissionDenied},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newRunbookServer(runbook.NewMemRepository(), noEmit{}, tc.callers)
			require.NotNil(t, srv)

			_, err := srv.GetRunbook(ctx, &pbs.GetRunbookRequest{Id: "rb_1234567890"})
			assert.Equal(t, tc.want, status.Code(err))
			_, err = srv.ListRunbooks(ctx, &pbs.ListRunbooksRequest{ScopeId: "global"})
			assert.Equal(t, tc.want, status.Code(err))
			_, err = srv.DeleteRunbook(ctx, &pbs.DeleteRunbookRequest{Id: "rb_1234567890"})
			assert.Equal(t, tc.want, status.Code(err))
		})
	}
}
