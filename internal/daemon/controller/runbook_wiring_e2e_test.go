// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package controller

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/runbook"
	runbookdb "github.com/hashicorp/boundary/internal/runbook/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runbookE2EController starts a controller with a real database. By default it
// uses the standard test database. Setting BOUNDARY_RUNBOOK_E2E_PG_URL points
// it at an existing database (and disables IPv6) for sandboxes without Docker
// or IPv6.
func runbookE2EController(t *testing.T) *TestController {
	t.Helper()
	opts := &TestControllerOpts{}
	if url := os.Getenv("BOUNDARY_RUNBOOK_E2E_PG_URL"); url != "" {
		cfg, err := config.DevController()
		require.NoError(t, err)
		opts.Config = cfg
		opts.DatabaseUrl = url
	}
	return NewTestController(t, opts)
}

func runbookGET(t *testing.T, tc *TestController, method, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, tc.ApiAddrs()[0]+path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tc.Token().Token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(b)
}

// TestRunbookAPI_EndToEnd drives the registered runbook API through the real
// HTTP gateway with a real token, real role grants stored in the database and
// a stored definition. It covers: no grant is refused (403), an explicit
// grant at global is allowed (200), wildcard grants never cover runbooks, a
// project-scoped grant covers only that project, and no token is 401.
func TestRunbookAPI_EndToEnd(t *testing.T) {
	ctx := context.Background()
	tc := runbookE2EController(t)
	defer tc.Shutdown()

	rw := db.New(tc.DbConn())
	repo, err := runbookdb.NewRepository(ctx, rw, rw, tc.Kms())
	require.NoError(t, err)
	seed := func(id, scope, name string) {
		t.Helper()
		def, err := runbook.NewStoredDefinition(id, scope, runbook.Definition{
			Name:        name,
			Interpreter: runbook.InterpreterPosixSh,
			Script:      []byte("echo hello\n"),
		}, "0123456789abcdef0123456789abcdef01234567", "runbooks/a.sh")
		require.NoError(t, err)
		_, err = repo.Create(ctx, def)
		require.NoError(t, err)
	}
	globalId, projectId := "rb_e2e_global", "rb_e2e_proj"
	seed(globalId, "global", "global-one")
	seed(projectId, tc.Server().DevProjectId, "proj-one")

	// No token: unauthenticated, not 500.
	req, err := http.NewRequest(http.MethodGet, tc.ApiAddrs()[0]+"/v1/runbooks/"+globalId, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// The admin token holds type=*;actions=* but that never covers runbooks.
	code, _ := runbookGET(t, tc, http.MethodGet, "/v1/runbooks/"+globalId)
	assert.Equal(t, http.StatusForbidden, code, "wildcard admin grants must not cover runbooks")
	code, _ = runbookGET(t, tc, http.MethodGet, "/v1/runbooks?scope_id=global")
	assert.Equal(t, http.StatusForbidden, code)

	grant := func(scopeId string, grants ...string) {
		t.Helper()
		client := tc.Client()
		client.SetToken(tc.Token().Token)
		rc := roles.NewClient(client)
		r, err := rc.Create(ctx, scopeId)
		require.NoError(t, err)
		u, err := rc.AddGrants(ctx, r.Item.Id, r.Item.Version, grants)
		require.NoError(t, err)
		_, err = rc.AddPrincipals(ctx, r.Item.Id, u.Item.Version, []string{tc.Token().UserId})
		require.NoError(t, err)
	}

	// A wildcard-type runbook-looking grant is still not enough.
	grant("global", "ids=*;type=*;actions=read,list,delete")
	code, _ = runbookGET(t, tc, http.MethodGet, "/v1/runbooks/"+globalId)
	assert.Equal(t, http.StatusForbidden, code)

	// Project-scoped explicit read grant: covers the project runbook only.
	grant(tc.Server().DevProjectId, "ids=*;type=runbook;actions=read")
	code, body := runbookGET(t, tc, http.MethodGet, "/v1/runbooks/"+projectId)
	assert.Equal(t, http.StatusOK, code, body)
	code, _ = runbookGET(t, tc, http.MethodGet, "/v1/runbooks/"+globalId)
	assert.Equal(t, http.StatusForbidden, code, "a project grant must not cover a global runbook")
	code, _ = runbookGET(t, tc, http.MethodDelete, "/v1/runbooks/"+projectId)
	assert.Equal(t, http.StatusForbidden, code, "read does not allow delete")

	// Explicit global grant: get, list and delete are allowed.
	grant("global", "ids=*;type=runbook;actions=read,list,delete")
	code, body = runbookGET(t, tc, http.MethodGet, "/v1/runbooks/"+globalId)
	assert.Equal(t, http.StatusOK, code, body)
	code, body = runbookGET(t, tc, http.MethodGet, "/v1/runbooks?scope_id=global")
	assert.Equal(t, http.StatusOK, code, body)
	assert.Contains(t, body, globalId)
	code, body = runbookGET(t, tc, http.MethodDelete, "/v1/runbooks/"+globalId)
	assert.Equal(t, http.StatusOK, code, body)
	code, _ = runbookGET(t, tc, http.MethodGet, "/v1/runbooks/"+globalId)
	assert.NotEqual(t, http.StatusOK, code, "deleted runbook must be gone")
}
