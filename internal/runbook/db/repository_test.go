// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package db

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/runbook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSHA = "0123456789abcdef0123456789abcdef01234567"
	canary  = "CANARY-SCRIPT-BODY-5f3a9c"
)

func testDef(name string) runbook.Definition {
	return runbook.Definition{
		Name:        name,
		Interpreter: runbook.InterpreterPosixSh,
		Parameters: []runbook.Parameter{
			{Name: "SERVICE", Type: runbook.TypeEnum, AllowedValues: []string{"web", "db"}, Required: true},
		},
		Script: []byte("echo " + canary + "\nsystemctl restart \"$SERVICE\"\n"),
	}
}

func mustStored(t *testing.T, id, scope, name string) runbook.StoredDefinition {
	t.Helper()
	s, err := runbook.NewStoredDefinition(id, scope, testDef(name), testSHA, "runbooks/restart.sh")
	require.NoError(t, err)
	return s
}

func TestRowRoundTrip(t *testing.T) {
	in := mustStored(t, "rb_roundtrip_01", "o_1234567890", "restart")
	in.Description = "restarts a service"
	in.Selector = runbook.TargetSelector{TargetIDs: []string{"ttcp_1234567890"}}
	row, err := toRow(in)
	require.NoError(t, err)
	assert.Equal(t, tableName, row.TableName())
	out, err := fromRow(row)
	require.NoError(t, err)
	assert.Equal(t, in, out)

	// no parameters is stored as an empty JSON array, never null
	in.Parameters = nil
	row, err = toRow(in)
	require.NoError(t, err)
	assert.Equal(t, "[]", row.Parameters)
	out, err = fromRow(row)
	require.NoError(t, err)
	assert.Empty(t, out.Parameters)

	row.Parameters = "{not json"
	_, err = fromRow(row)
	require.ErrorIs(t, err, runbook.ErrInvalidInput)
}

func TestNewRepositoryRequiresDeps(t *testing.T) {
	_, err := NewRepository(context.Background(), nil, nil, nil)
	require.ErrorIs(t, err, runbook.ErrInvalidInput)
}

// TestWriteValidation covers the checks made before the database or kms is
// touched, so it needs neither.
func TestWriteValidation(t *testing.T) {
	r := &Repository{}
	ctx := context.Background()
	good := func() runbook.StoredDefinition { return mustStored(t, "rb_valid_00001", "o_1234567890", "ok") }
	mut := map[string]func(*runbook.StoredDefinition){
		"no id":      func(d *runbook.StoredDefinition) { d.Id = "" },
		"no scope":   func(d *runbook.StoredDefinition) { d.ScopeId = "" },
		"no name":    func(d *runbook.StoredDefinition) { d.Name = "" },
		"branch ref": func(d *runbook.StoredDefinition) { d.SourceCommitSHA = "main" },
		"bad sha256": func(d *runbook.StoredDefinition) { d.ScriptSHA256 = "xyz" },
		"bad interp": func(d *runbook.StoredDefinition) { d.Interpreter = "bash" },
		"traversal":  func(d *runbook.StoredDefinition) { d.ScriptPath = "../x.sh" },
	}
	for name, f := range mut {
		t.Run(name, func(t *testing.T) {
			d := good()
			f(&d)
			_, err := r.Create(ctx, d)
			require.ErrorIs(t, err, runbook.ErrInvalidInput)
			d.Version = 1
			_, err = r.Update(ctx, d)
			require.ErrorIs(t, err, runbook.ErrInvalidInput)
		})
	}
	d := good()
	d.Version = 2
	_, err := r.Create(ctx, d)
	require.ErrorIs(t, err, runbook.ErrInvalidInput)
	d = good()
	_, err = r.Update(ctx, d) // version zero
	require.ErrorIs(t, err, runbook.ErrInvalidInput)
	_, err = r.Get(ctx, "")
	require.ErrorIs(t, err, runbook.ErrInvalidInput)
	_, err = r.List(ctx, "")
	require.ErrorIs(t, err, runbook.ErrInvalidInput)

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = r.List(cctx, "o_1234567890")
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, r.Delete(cctx, "rb_x"), context.Canceled)
}

func testDB(t *testing.T) *db.DB {
	t.Helper()
	if os.Getenv("TEST_DB_PORT") == "" && os.Getenv("TEST_DB_HOST") == "" {
		if _, err := os.Stat("/var/run/docker.sock"); err != nil {
			t.Skip("no database available: set TEST_DB_HOST/TEST_DB_PORT or run docker")
		}
	}
	conn, _ := db.TestSetup(t, "postgres")
	return conn
}

// repoContract is the behaviour every runbook.Repository must share; it is the
// same sequence the MemRepository passes.
func repoContract(t *testing.T, repo runbook.Repository, scope, otherScope string) {
	ctx := context.Background()

	a, err := repo.Create(ctx, mustStored(t, "rb_contract_001", scope, "b-runbook"))
	require.NoError(t, err)
	assert.EqualValues(t, 1, a.Version)
	_, err = repo.Create(ctx, mustStored(t, "rb_contract_002", scope, "a-runbook"))
	require.NoError(t, err)
	_, err = repo.Create(ctx, mustStored(t, "rb_contract_003", otherScope, "a-runbook"))
	require.NoError(t, err, "same name in another scope is allowed")

	_, err = repo.Create(ctx, mustStored(t, "rb_contract_001", scope, "other-name"))
	require.ErrorIs(t, err, runbook.ErrAlreadyExists)
	_, err = repo.Create(ctx, mustStored(t, "rb_contract_004", scope, "a-runbook"))
	require.ErrorIs(t, err, runbook.ErrAlreadyExists)

	got, err := repo.Get(ctx, "rb_contract_001")
	require.NoError(t, err)
	assert.Equal(t, a, got)
	_, err = repo.Get(ctx, "rb_missing_0001")
	require.ErrorIs(t, err, runbook.ErrNotFound)

	list, err := repo.List(ctx, scope)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, []string{"a-runbook", "b-runbook"}, []string{list[0].Name, list[1].Name})
	for _, d := range list {
		assert.Equal(t, scope, d.ScopeId, "List must never return another scope")
	}

	// update
	upd := got
	upd.Description = "now described"
	upd.Selector = runbook.TargetSelector{AllTargets: true}
	u, err := repo.Update(ctx, upd)
	require.NoError(t, err)
	assert.EqualValues(t, 2, u.Version)
	assert.Equal(t, "now described", u.Description)
	assert.True(t, u.Selector.AllTargets)

	// stale version
	_, err = repo.Update(ctx, upd)
	require.ErrorIs(t, err, runbook.ErrVersionConflict)

	// clearing the description
	u.Description = ""
	u2, err := repo.Update(ctx, u)
	require.NoError(t, err)
	assert.Equal(t, "", u2.Description)

	// scope is immutable
	moved := u2
	moved.ScopeId = otherScope
	_, err = repo.Update(ctx, moved)
	require.ErrorIs(t, err, runbook.ErrInvalidInput)
	// renaming onto a taken name
	clash := u2
	clash.Name = "a-runbook"
	_, err = repo.Update(ctx, clash)
	require.ErrorIs(t, err, runbook.ErrAlreadyExists)
	// updating something that does not exist
	ghost := mustStored(t, "rb_missing_0001", scope, "ghost")
	ghost.Version = 1
	_, err = repo.Update(ctx, ghost)
	require.ErrorIs(t, err, runbook.ErrNotFound)

	// delete
	require.NoError(t, repo.Delete(ctx, "rb_contract_001"))
	require.ErrorIs(t, repo.Delete(ctx, "rb_contract_001"), runbook.ErrNotFound)
	_, err = repo.Get(ctx, "rb_contract_001")
	require.ErrorIs(t, err, runbook.ErrNotFound)
}

func TestMemRepositoryContract(t *testing.T) {
	repoContract(t, runbook.NewMemRepository(), "o_1234567890", "o_0987654321")
}

func TestDBRepositoryContract(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	k := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	other := iam.TestOrg(t, iamRepo)

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, k)
	require.NoError(t, err)
	repoContract(t, repo, org.PublicId, other.PublicId)

	t.Run("oplog entries are written", func(t *testing.T) {
		require.NoError(t, db.TestVerifyOplog(t, rw, "rb_contract_002", db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(time.Minute)))
		require.NoError(t, db.TestVerifyOplog(t, rw, "rb_contract_001", db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(time.Minute)))
		// rb_contract_001 is deleted at the end of the contract sequence
		require.NoError(t, db.TestVerifyOplog(t, rw, "rb_contract_001", db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(time.Minute)))
	})
	t.Run("unknown scope", func(t *testing.T) {
		_, err := repo.Create(ctx, mustStored(t, "rb_unknown_scp1", "o_doesnotexist", "x"))
		require.ErrorIs(t, err, runbook.ErrInvalidInput)
	})
	t.Run("canary script body never stored or leaked", func(t *testing.T) {
		d := mustStored(t, "rb_canary_0001", org.PublicId, "canary")
		_, err := repo.Create(ctx, d)
		require.NoError(t, err)
		_, err = repo.Create(ctx, d) // unique violation
		require.Error(t, err)
		assert.False(t, strings.Contains(err.Error(), canary))
		assert.True(t, errors.Is(err, runbook.ErrAlreadyExists))
		var n int
		rows, err := rw.Query(ctx, "select count(*) from runbook_definition where to_jsonb(runbook_definition)::text like ?", []any{"%" + canary + "%"})
		require.NoError(t, err)
		defer rows.Close()
		require.True(t, rows.Next())
		require.NoError(t, rows.Scan(&n))
		assert.Zero(t, n)
	})
}
