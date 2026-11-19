// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbooks

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type ctxCaller struct{}
type callerKey struct{}

func (ctxCaller) Caller(ctx context.Context) (Caller, error) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	if !ok {
		return Caller{}, errors.New("none")
	}
	return c, nil
}

func asCaller(c Caller) context.Context {
	return context.WithValue(context.Background(), callerKey{}, c)
}

func TestGRPC_ReadAndDelete(t *testing.T) {
	s, em, _ := newSvc(t)
	adm := admin(t)
	created, err := s.Create(context.Background(), adm, req("echo hi # "+canary))
	require.NoError(t, err)
	g, err := NewGRPCService(s, ctxCaller{})
	require.NoError(t, err)

	// unauthenticated and no-grant callers are refused
	_, err = g.GetRunbook(context.Background(), &services.GetRunbookRequest{Id: created.Id})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	nobody := Caller{UserId: "u_nobody0000", ACL: acl(t, scopeA)}
	_, err = g.GetRunbook(asCaller(nobody), &services.GetRunbookRequest{Id: created.Id})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = g.GetRunbook(asCaller(adm), &services.GetRunbookRequest{Id: "rb_missing"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "missing looks like forbidden")

	resp, err := g.GetRunbook(asCaller(adm), &services.GetRunbookRequest{Id: created.Id})
	require.NoError(t, err)
	assert.Equal(t, created.Id, resp.Item.Id)
	assert.Equal(t, sha40, resp.Item.CommitSha)
	raw, err := proto.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), canary, "script body must never be returned")

	lr, err := g.ListRunbooks(asCaller(adm), &services.ListRunbooksRequest{ScopeId: scopeA})
	require.NoError(t, err)
	assert.Len(t, lr.Items, 1)
	_, err = g.ListRunbooks(asCaller(adm), &services.ListRunbooksRequest{ScopeId: scopeA, Recursive: true})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = g.ListRunbooks(asCaller(nobody), &services.ListRunbooksRequest{ScopeId: scopeA})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// create/update are not exposed yet
	_, err = g.CreateRunbook(asCaller(adm), &services.CreateRunbookRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = g.UpdateRunbook(asCaller(adm), &services.UpdateRunbookRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))

	before := len(em.events)
	_, err = g.DeleteRunbook(asCaller(nobody), &services.DeleteRunbookRequest{Id: created.Id})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = g.DeleteRunbook(asCaller(adm), &services.DeleteRunbookRequest{Id: created.Id})
	require.NoError(t, err)
	assert.Equal(t, before+1, len(em.events))
}

func TestNewGRPCService_FailsClosed(t *testing.T) {
	_, err := NewGRPCService(nil, nil)
	require.Error(t, err)
}
