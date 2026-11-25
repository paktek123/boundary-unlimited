// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package controller

import (
	"context"
	"net"
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/runbooks"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/runbook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type fixedCaller struct{ c runbooks.Caller }

func (f fixedCaller) Caller(context.Context) (runbooks.Caller, error) { return f.c, nil }

func grantACL(t *testing.T, grants ...string) perms.ACL {
	t.Helper()
	var gs []perms.Grant
	for _, g := range grants {
		p, err := perms.Parse(context.Background(), perms.GrantTuple{RoleScopeId: "global", GrantScopeId: "global", Grant: g})
		require.NoError(t, err, g)
		gs = append(gs, p)
	}
	return perms.NewACL(gs...)
}

// TestRunbookReadDelete_Grants checks, through the wrapper actually
// registered in the controller, that each served RPC needs an explicit
// `runbook` grant (wildcard type grants never cover runbooks) and that Create
// and Update are never served. It uses the in-memory repository: the DB-backed
// variant needs Postgres (see the PR description).
func TestRunbookReadDelete_Grants(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		grants  []string
		allowed bool
	}{
		{"explicit grant", []string{"ids=*;type=runbook;actions=read,list,delete"}, true},
		{"no grants", nil, false},
		{"wildcard type", []string{"ids=*;type=*;actions=*"}, false},
		{"read only", []string{"ids=*;type=runbook;actions=read"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := runbook.NewMemRepository()
			caller := runbooks.Caller{UserId: "u_1234567890", ACL: grantACL(t, tc.grants...)}
			srv := newRunbookServer(repo, noEmit{}, fixedCaller{c: caller})
			require.NotNil(t, srv)

			_, getErr := srv.GetRunbook(ctx, &pbs.GetRunbookRequest{Id: "rb_0000000001"})
			_, listErr := srv.ListRunbooks(ctx, &pbs.ListRunbooksRequest{ScopeId: "global"})
			_, delErr := srv.DeleteRunbook(ctx, &pbs.DeleteRunbookRequest{Id: "rb_0000000001"})
			if !tc.allowed {
				for name, err := range map[string]error{"get": getErr, "list": listErr, "delete": delErr} {
					assert.Equal(t, codes.PermissionDenied, status.Code(err), name)
				}
			} else {
				// Authorised for list; get/delete of a missing id are indistinguishable from forbidden.
				assert.NoError(t, listErr)
			}

			_, err := srv.CreateRunbook(ctx, &pbs.CreateRunbookRequest{})
			assert.Equal(t, codes.Unimplemented, status.Code(err))
			_, err = srv.UpdateRunbook(ctx, &pbs.UpdateRunbookRequest{})
			assert.Equal(t, codes.Unimplemented, status.Code(err))
		})
	}
}

// TestRunbookService_UnregisteredIsUnimplemented checks that a gRPC server
// without the runbook service (the fail-closed state the HTTP gateway proxies
// to) answers with a clean Unimplemented status, not an internal error.
func TestRunbookService_UnregisteredIsUnimplemented(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := grpc.NewServer()
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = pbs.NewRunbookServiceClient(conn).GetRunbook(context.Background(), &pbs.GetRunbookRequest{Id: "rb_0000000001"})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}
