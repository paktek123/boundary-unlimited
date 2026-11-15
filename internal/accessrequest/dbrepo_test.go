// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTextArrayRoundTrip(t *testing.T) {
	cases := [][]string{
		{"a"},
		{"ids=*;type=target;actions=read", "ids=a,b;actions=*"},
		{`quote"inside`, `back\slash`, "comma,here", "{braces}", " spaced "},
		{"NULL", ""},
	}
	for _, in := range cases {
		out, err := decodeTextArray(encodeTextArray(in))
		require.NoError(t, err)
		assert.Equal(t, in, out)
	}
	// unquoted postgres output also parses
	out, err := decodeTextArray("{a,b}")
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, out)
	for _, bad := range []string{"", "a,b", "{\"a}", "{a,}", "{\"a\"b}"} {
		_, err := decodeTextArray(bad)
		assert.Error(t, err, bad)
	}
}

func TestNewDBRepositoryRequiresDeps(t *testing.T) {
	_, err := NewDBRepository(context.Background(), nil, nil, nil)
	require.ErrorIs(t, err, ErrInvalidInput)
}

// TestDBRepositoryCreateValidation covers the checks made before the database
// or kms is touched, so it needs neither.
func TestDBRepositoryCreateValidation(t *testing.T) {
	d := &DBRepository{}
	good := func() Request {
		r := mk(t, "ar_valid_0001", "u_requester", t0)
		r.ScopeId = "o_1234567890"
		return r
	}
	mut := map[string]func(*Request){
		"no id":           func(r *Request) { r.Id = "" },
		"version":         func(r *Request) { r.Version = 1 },
		"no scope":        func(r *Request) { r.ScopeId = "" },
		"no requester":    func(r *Request) { r.RequesterId = "" },
		"approved":        func(r *Request) { r.State = StateApproved },
		"past expiry":     func(r *Request) { r.ExpiresAt = t0.Add(-time.Hour) },
		"future expiry":   func(r *Request) { r.ExpiresAt = t0.Add(time.Hour) },
		"decided":         func(r *Request) { r.DecidedBy = "u_other" },
		"no grants":       func(r *Request) { r.Grants = nil },
		"empty grant":     func(r *Request) { r.Grants = []string{" "} },
		"no justify":      func(r *Request) { r.Justification = " " },
		"zero duration":   func(r *Request) { r.Duration = 0 },
		"fractional secs": func(r *Request) { r.Duration = 1500 * time.Millisecond },
		"bad hash":        func(r *Request) { r.GrantHash = "deadbeef" },
	}
	for name, f := range mut {
		t.Run(name, func(t *testing.T) {
			r := good()
			f(&r)
			_, err := d.Create(context.Background(), r)
			require.ErrorIs(t, err, ErrInvalidInput)
		})
	}
}

func TestDBRepositoryNotImplemented(t *testing.T) {
	d := &DBRepository{}
	_, err := d.List(context.Background(), ListFilter{})
	require.ErrorIs(t, err, ErrNotImplemented)
	_, err = d.Update(context.Background(), Request{})
	require.ErrorIs(t, err, ErrNotImplemented)
}

// contract is the Create/Get behaviour every Repository must share. ids must
// be long enough for the database's public id check.
func contract(t *testing.T, repo Repository, scopeId, requesterId string) {
	ctx := context.Background()
	req := func(id string) Request {
		r := mk(t, id, requesterId, t0)
		r.ScopeId = scopeId
		return r
	}

	created, err := repo.Create(ctx, req("ar_contract_01"))
	require.NoError(t, err)
	assert.EqualValues(t, 1, created.Version)
	assert.Equal(t, StatePending, created.State)
	assert.Equal(t, requesterId, created.RequesterId)

	got, err := repo.Get(ctx, "ar_contract_01")
	require.NoError(t, err)
	assert.Equal(t, "ar_contract_01", got.Id)
	assert.Equal(t, requesterId, got.RequesterId)
	assert.Equal(t, scopeId, got.ScopeId)
	assert.Equal(t, []string{"g"}, got.Grants)
	assert.Equal(t, "why", got.Justification)
	assert.Equal(t, time.Hour, got.Duration)
	assert.Equal(t, StatePending, got.State)
	assert.EqualValues(t, 1, got.Version)

	_, err = repo.Create(ctx, req("ar_contract_01"))
	require.ErrorIs(t, err, ErrAlreadyExists)

	bad := req("ar_contract_02")
	bad.Version = 3
	_, err = repo.Create(ctx, bad)
	require.ErrorIs(t, err, ErrInvalidInput)

	_, err = repo.Get(ctx, "ar_missing_001")
	require.ErrorIs(t, err, ErrNotFound)

	// returned values are copies
	got.Grants[0] = "mutated"
	again, err := repo.Get(ctx, "ar_contract_01")
	require.NoError(t, err)
	assert.Equal(t, []string{"g"}, again.Grants)
}

func TestMemRepositoryContract(t *testing.T) {
	contract(t, NewMemRepository(), "o_1234567890", "u_requester")
}

// testDB returns a migrated database, skipping the test when neither a
// database server (TEST_DB_PORT / TEST_DB_HOST) nor docker is available.
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

func TestDBRepositoryContract(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	k := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	user := iam.TestUser(t, iamRepo, org.PublicId)

	rw := db.New(conn)
	repo, err := NewDBRepository(ctx, rw, rw, k)
	require.NoError(t, err)
	contract(t, repo, org.PublicId, user.PublicId)

	t.Run("grants with special characters", func(t *testing.T) {
		r := mk(t, "ar_special_001", user.PublicId, t0)
		r.ScopeId = org.PublicId
		r.Grants = []string{`ids=*;type=target;actions=read`, `we"ird,\grant{}`}
		_, err := repo.Create(ctx, r)
		require.NoError(t, err)
		got, err := repo.Get(ctx, r.Id)
		require.NoError(t, err)
		assert.Equal(t, r.Grants, got.Grants)
		assert.Equal(t, GrantHash(r.Grants), got.GrantHash)
	})
	t.Run("unknown requester or scope", func(t *testing.T) {
		r := mk(t, "ar_unknown_01", "u_doesnotexist", t0)
		r.ScopeId = org.PublicId
		_, err := repo.Create(ctx, r)
		require.ErrorIs(t, err, ErrInvalidInput)
		r = mk(t, "ar_unknown_02", user.PublicId, t0)
		r.ScopeId = "o_doesnotexist"
		_, err = repo.Create(ctx, r)
		require.Error(t, err)
	})
	t.Run("oplog entry is written", func(t *testing.T) {
		require.NoError(t, db.TestVerifyOplog(t, rw, "ar_contract_01", db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(time.Minute)))
	})
	t.Run("short id rejected by the database", func(t *testing.T) {
		r := mk(t, "short", user.PublicId, t0)
		r.ScopeId = org.PublicId
		_, err := repo.Create(ctx, r)
		require.ErrorIs(t, err, ErrInvalidInput)
	})
}
