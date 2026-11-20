// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbooks

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/runbooks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
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
	nobody := Caller{UserId: "u_nobody0000", ACL: acl(t, scopeA)}

	t.Run("unauthenticated and no-grant callers are refused", func(t *testing.T) {
		_, err := g.GetRunbook(context.Background(), &services.GetRunbookRequest{Id: created.Id})
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		_, err = g.GetRunbook(asCaller(nobody), &services.GetRunbookRequest{Id: created.Id})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		_, err = g.GetRunbook(asCaller(adm), &services.GetRunbookRequest{Id: "rb_missing"})
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "missing looks like forbidden")
	})

	t.Run("get never returns the script body", func(t *testing.T) {
		resp, err := g.GetRunbook(asCaller(adm), &services.GetRunbookRequest{Id: created.Id})
		require.NoError(t, err)
		assert.Equal(t, created.Id, resp.Item.Id)
		assert.Equal(t, sha40, resp.Item.CommitSha)
		raw, err := proto.Marshal(resp)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), canary, "script body must never be returned")
	})

	t.Run("list", func(t *testing.T) {
		lr, err := g.ListRunbooks(asCaller(adm), &services.ListRunbooksRequest{ScopeId: scopeA})
		require.NoError(t, err)
		assert.Len(t, lr.Items, 1)
		_, err = g.ListRunbooks(asCaller(adm), &services.ListRunbooksRequest{ScopeId: scopeA, Recursive: true})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		_, err = g.ListRunbooks(asCaller(nobody), &services.ListRunbooksRequest{ScopeId: scopeA})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("create and update without an item are invalid", func(t *testing.T) {
		_, err := g.CreateRunbook(asCaller(adm), &services.CreateRunbookRequest{})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		_, err = g.UpdateRunbook(asCaller(adm), &services.UpdateRunbookRequest{})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("delete is authorised and audited", func(t *testing.T) {
		before := len(em.events)
		_, err := g.DeleteRunbook(asCaller(nobody), &services.DeleteRunbookRequest{Id: created.Id})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		_, err = g.DeleteRunbook(asCaller(adm), &services.DeleteRunbookRequest{Id: created.Id})
		require.NoError(t, err)
		assert.Equal(t, before+1, len(em.events))
	})
}

func TestGRPCErr(t *testing.T) {
	tests := []struct {
		err  error
		want codes.Code
	}{
		{ErrForbidden, codes.PermissionDenied},
		{ErrNotFound, codes.PermissionDenied},
		{ErrInvalid, codes.InvalidArgument},
		{ErrConflict, codes.Aborted},
		{ErrRunNotSupported, codes.Internal},
		{errors.New("boom"), codes.Internal},
	}
	for _, tc := range tests {
		t.Run(tc.err.Error(), func(t *testing.T) {
			assert.Equal(t, tc.want, status.Code(grpcErr(fmt.Errorf("wrapped: %w", tc.err))))
		})
	}
}

func TestNewGRPCService_FailsClosed(t *testing.T) {
	_, err := NewGRPCService(nil, nil)
	require.Error(t, err)
}

func TestGRPC_CreateUpdatePinned(t *testing.T) {
	s, em, repo := newSvc(t)
	adm := admin(t)
	g, err := NewGRPCService(s, ctxCaller{})
	require.NoError(t, err)
	item := func() *pb.Runbook {
		return &pb.Runbook{ScopeId: scopeA, Name: "restart", Interpreter: "sh", CommitSha: sha40,
			ScriptPath: "ops/run.sh", Selector: &pb.RunbookTargetSelector{AllTargets: true},
			// Output-only fields are ignored.
			ScriptSha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
	}

	t.Run("no grant is refused", func(t *testing.T) {
		_, err := g.CreateRunbook(asCaller(Caller{UserId: "u_nobody0000", ACL: acl(t, scopeA)}), &services.CreateRunbookRequest{Item: item()})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		_, err = g.CreateRunbook(context.Background(), &services.CreateRunbookRequest{Item: item()})
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
	t.Run("branch and short sha are rejected", func(t *testing.T) {
		for _, sha := range []string{"main", "0123abc"} {
			it := item()
			it.CommitSha = sha
			_, err := g.CreateRunbook(asCaller(adm), &services.CreateRunbookRequest{Item: it})
			assert.Equal(t, codes.InvalidArgument, status.Code(err), sha)
		}
	})
	var created *pb.Runbook
	t.Run("create is unverified and audited with pin only", func(t *testing.T) {
		resp, err := g.CreateRunbook(asCaller(adm), &services.CreateRunbookRequest{Item: item()})
		require.NoError(t, err)
		created = resp.Item
		assert.Empty(t, created.ScriptSha256, "client-supplied hash must be ignored")
		stored, err := repo.Get(context.Background(), created.Id)
		require.NoError(t, err)
		assert.False(t, stored.Verified())
		require.Len(t, em.events, 1)
		assert.Equal(t, sha40, em.events[0].CommitSHA)
		assert.Equal(t, adm.UserId, em.events[0].PrincipalId)
	})
	t.Run("update changing the pin stays unverified; mask unsupported", func(t *testing.T) {
		it := item()
		it.CommitSha = "fedcba9876543210fedcba9876543210fedcba98"
		it.Version = created.Version
		_, err := g.UpdateRunbook(asCaller(adm), &services.UpdateRunbookRequest{Id: created.Id, Item: it,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"name"}}})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		resp, err := g.UpdateRunbook(asCaller(adm), &services.UpdateRunbookRequest{Id: created.Id, Item: it})
		require.NoError(t, err)
		assert.Equal(t, uint32(2), resp.Item.Version)
		stored, _ := repo.Get(context.Background(), created.Id)
		assert.False(t, stored.Verified())
		_, err = g.UpdateRunbook(asCaller(adm), &services.UpdateRunbookRequest{Id: created.Id, Item: it}) // stale version
		assert.Equal(t, codes.Aborted, status.Code(err))
		it.Version = 0
		_, err = g.UpdateRunbook(asCaller(adm), &services.UpdateRunbookRequest{Id: created.Id, Item: it})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}
