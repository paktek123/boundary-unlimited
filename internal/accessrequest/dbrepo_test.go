// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"os"
	"sync"
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

// TestDBRepositoryUpdateValidation covers the checks made before the database
// is touched, so it needs none.
func TestDBRepositoryUpdateValidation(t *testing.T) {
	d := &DBRepository{}
	_, err := d.Update(context.Background(), Request{})
	require.ErrorIs(t, err, ErrInvalidInput)
	_, err = d.Update(context.Background(), Request{Id: "ar_x_00000001"}) // version zero
	require.ErrorIs(t, err, ErrInvalidInput)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = d.Update(ctx, Request{Id: "ar_x_00000001", Version: 1})
	require.ErrorIs(t, err, context.Canceled)
}

func TestTransitionOK(t *testing.T) {
	all := []State{StatePending, StateApproved, StateDenied, StateCancelled, StateExpired, StateRevoked}
	want := map[[2]State]bool{
		{StatePending, StateApproved}:  true,
		{StatePending, StateDenied}:    true,
		{StatePending, StateCancelled}: true,
		{StatePending, StateExpired}:   true,
		{StateApproved, StateExpired}:  true,
		{StateApproved, StateRevoked}:  true,
	}
	for _, from := range all {
		for _, to := range all {
			assert.Equal(t, want[[2]State{from, to}], transitionOK(from, to), "%s -> %s", from, to)
		}
	}
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

func TestDBRepositoryListValidation(t *testing.T) {
	d := &DBRepository{}
	_, err := d.List(context.Background(), ListFilter{States: []State{"bogus"}})
	require.ErrorIs(t, err, ErrInvalidState)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = d.List(ctx, ListFilter{})
	require.ErrorIs(t, err, context.Canceled)
	// a filter that excludes approved can never have active results, and
	// does not reach the (nil) database
	got, err := d.ListActive(context.Background(), ListFilter{States: []State{StatePending, StateDenied}})
	require.NoError(t, err)
	assert.Empty(t, got)
}

// activeContract checks List scoping and ListActive. setState forces a stored
// request into a state with the given expiry; the repositories under test
// have no transition API yet, so each variant supplies its own way.
func activeContract(t *testing.T, repo interface {
	Repository
	ActiveLister
}, scopeId, otherScopeId, requesterId, otherRequesterId string, now time.Time,
	create func(id, scope, requester string),
	setState func(id string, st State, expiry time.Time)) {
	ctx := context.Background()
	for _, id := range []string{"ar_act_pending", "ar_act_denied", "ar_act_cancel", "ar_act_expired",
		"ar_act_revoked", "ar_act_live", "ar_act_boundary", "ar_act_past", "ar_act_nextday"} {
		create(id, scopeId, requesterId)
	}
	create("ar_act_other_scope", otherScopeId, requesterId)
	create("ar_act_other_user", scopeId, otherRequesterId)

	setState("ar_act_denied", StateDenied, time.Time{})
	setState("ar_act_cancel", StateCancelled, time.Time{})
	setState("ar_act_expired", StateExpired, time.Time{})
	setState("ar_act_revoked", StateRevoked, time.Time{})
	setState("ar_act_live", StateApproved, now.Add(time.Hour))
	setState("ar_act_nextday", StateApproved, now.Add(24*time.Hour))
	setState("ar_act_boundary", StateApproved, now) // expires_at == now is expired
	setState("ar_act_past", StateApproved, now.Add(-time.Second))
	setState("ar_act_other_scope", StateApproved, now.Add(time.Hour))
	setState("ar_act_other_user", StateApproved, now.Add(time.Hour))

	ids := func(rs []Request) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Id)
		}
		return out
	}
	active, err := repo.ListActive(ctx, ListFilter{ScopeId: scopeId, RequesterId: requesterId})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"ar_act_live", "ar_act_nextday"}, ids(active))
	for _, r := range active {
		assert.Equal(t, StateApproved, r.State)
		assert.Equal(t, scopeId, r.ScopeId)
		assert.True(t, now.Before(r.ExpiresAt))
	}

	// a state filter can only narrow the active result, never widen it
	for _, st := range []State{StatePending, StateDenied, StateCancelled, StateExpired, StateRevoked} {
		got, err := repo.ListActive(ctx, ListFilter{ScopeId: scopeId, States: []State{st}})
		require.NoError(t, err)
		assert.Empty(t, got, st)
	}
	got, err := repo.ListActive(ctx, ListFilter{ScopeId: scopeId, States: []State{StatePending, StateApproved}})
	require.NoError(t, err)
	assert.Len(t, got, 3) // live, nextday, other_user

	// without a scope the other scope is visible; with one it never is
	all, err := repo.List(ctx, ListFilter{})
	require.NoError(t, err)
	assert.Contains(t, ids(all), "ar_act_other_scope")
	scoped, err := repo.List(ctx, ListFilter{ScopeId: scopeId})
	require.NoError(t, err)
	assert.NotContains(t, ids(scoped), "ar_act_other_scope")
	assert.Len(t, scoped, 10)
	other, err := repo.List(ctx, ListFilter{ScopeId: otherScopeId})
	require.NoError(t, err)
	assert.Equal(t, []string{"ar_act_other_scope"}, ids(other))

	pend, err := repo.List(ctx, ListFilter{ScopeId: scopeId, States: []State{StatePending}})
	require.NoError(t, err)
	assert.Equal(t, []string{"ar_act_pending"}, ids(pend))
	byUser, err := repo.List(ctx, ListFilter{ScopeId: scopeId, RequesterId: otherRequesterId})
	require.NoError(t, err)
	assert.Equal(t, []string{"ar_act_other_user"}, ids(byUser))

	// ordering is stable: creation time then id
	for i := 1; i < len(scoped); i++ {
		a, b := scoped[i-1], scoped[i]
		assert.True(t, a.CreatedAt.Before(b.CreatedAt) || (a.CreatedAt.Equal(b.CreatedAt) && a.Id < b.Id))
	}
}

func TestMemRepositoryActiveContract(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	repo := NewMemRepositoryWithClock(func() time.Time { return now })
	n := 0
	create := func(id, scope, requester string) {
		r := mk(t, id, requester, t0.Add(time.Duration(n)*time.Second))
		n++
		r.ScopeId = scope
		_, err := repo.Create(context.Background(), r)
		require.NoError(t, err)
	}
	setState := func(id string, st State, expiry time.Time) {
		cur, err := repo.Get(context.Background(), id)
		require.NoError(t, err)
		cur.State, cur.ExpiresAt = st, expiry
		_, err = repo.Update(context.Background(), cur)
		require.NoError(t, err)
	}
	activeContract(t, repo, "o_1234567890", "o_0987654321", "u_requester", "u_other_user", now, create, setState)
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
	t.Run("list and active", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		clockRepo, err := NewDBRepository(ctx, rw, rw, k, WithClock(func() time.Time { return now }))
		require.NoError(t, err)
		// fresh scopes, so rows made by the other subtests do not appear
		scopeA, scopeB := iam.TestOrg(t, iamRepo), iam.TestOrg(t, iamRepo)
		user2 := iam.TestUser(t, iamRepo, scopeA.PublicId)
		create := func(id, scope, requester string) {
			r := mk(t, id, requester, t0)
			r.ScopeId = scope
			_, err := clockRepo.Create(ctx, r)
			require.NoError(t, err)
		}
		approver := iam.TestUser(t, iamRepo, scopeA.PublicId)
		// Real transitions through Update; the transition trigger stays on.
		setState := func(id string, st State, expiry time.Time) {
			cur, err := clockRepo.Get(ctx, id)
			require.NoError(t, err)
			step := func(to State, by string, exp time.Time) {
				cur.State, cur.DecidedBy, cur.ExpiresAt = to, by, exp
				cur, err = clockRepo.Update(ctx, cur)
				require.NoError(t, err)
			}
			switch st {
			case StateDenied:
				step(StateDenied, approver.PublicId, time.Time{})
			case StateCancelled:
				step(StateCancelled, cur.RequesterId, time.Time{})
			case StateExpired:
				step(StateExpired, "", time.Time{})
			case StateRevoked:
				step(StateApproved, approver.PublicId, expiry.Add(time.Hour))
				step(StateRevoked, approver.PublicId, expiry.Add(time.Hour))
			case StateApproved:
				step(StateApproved, approver.PublicId, expiry)
			}
		}
		activeContract(t, clockRepo, scopeA.PublicId, scopeB.PublicId, user.PublicId, user2.PublicId, now, create, setState)
	})
	t.Run("transitions", func(t *testing.T) {
		scope := iam.TestOrg(t, iamRepo)
		requester := iam.TestUser(t, iamRepo, scope.PublicId)
		approver := iam.TestUser(t, iamRepo, scope.PublicId)
		other := iam.TestUser(t, iamRepo, scope.PublicId)
		newReq := func(id string) Request {
			r := mk(t, id, requester.PublicId, t0)
			r.ScopeId = scope.PublicId
			got, err := repo.Create(ctx, r)
			require.NoError(t, err)
			return got
		}
		exp := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)

		// approve, then revoke
		r := newReq("ar_trans_00001")
		r.State, r.DecidedBy, r.ExpiresAt = StateApproved, approver.PublicId, exp
		r, err := repo.Update(ctx, r)
		require.NoError(t, err)
		assert.Equal(t, StateApproved, r.State)
		assert.EqualValues(t, 2, r.Version)
		assert.WithinDuration(t, exp, r.ExpiresAt, time.Second)
		decided, err := repo.List(ctx, ListFilter{ScopeId: scope.PublicId, ApproverId: approver.PublicId})
		require.NoError(t, err)
		require.Len(t, decided, 1)
		assert.Equal(t, approver.PublicId, decided[0].DecidedBy)
		r.State, r.DecidedBy = StateRevoked, approver.PublicId
		r, err = repo.Update(ctx, r)
		require.NoError(t, err)
		assert.Equal(t, StateRevoked, r.State)

		// a terminal request can never change again
		back := r
		back.State = StateApproved
		_, err = repo.Update(ctx, back)
		require.ErrorIs(t, err, ErrInvalidTransition)

		// self approval and deny are rejected
		r = newReq("ar_trans_00002")
		self := r
		self.State, self.DecidedBy, self.ExpiresAt = StateApproved, requester.PublicId, exp
		_, err = repo.Update(ctx, self)
		require.ErrorIs(t, err, ErrSelfApproval)
		self.State = StateDenied
		_, err = repo.Update(ctx, self)
		require.ErrorIs(t, err, ErrSelfApproval)
		// only the requester may cancel
		c := r
		c.State, c.DecidedBy = StateCancelled, other.PublicId
		_, err = repo.Update(ctx, c)
		require.ErrorIs(t, err, ErrNotRequester)
		c.DecidedBy = requester.PublicId
		c, err = repo.Update(ctx, c)
		require.NoError(t, err)
		assert.Equal(t, StateCancelled, c.State)

		// pending -> revoked is invalid; the grants cannot change
		r = newReq("ar_trans_00003")
		bad := r
		bad.State, bad.DecidedBy = StateRevoked, approver.PublicId
		_, err = repo.Update(ctx, bad)
		require.ErrorIs(t, err, ErrInvalidTransition)
		bad = r
		bad.State, bad.DecidedBy, bad.ExpiresAt, bad.Grants = StateApproved, approver.PublicId, exp, []string{"ids=*;type=*;actions=*"}
		_, err = repo.Update(ctx, bad)
		require.ErrorIs(t, err, ErrInvalidInput)

		// stale version is a conflict, not a state change
		stale := r
		stale.Version = 7
		stale.State, stale.DecidedBy = StateDenied, approver.PublicId
		_, err = repo.Update(ctx, stale)
		require.ErrorIs(t, err, ErrVersionConflict)
		still, err := repo.Get(ctx, r.Id)
		require.NoError(t, err)
		assert.Equal(t, StatePending, still.State)

		// concurrent decisions: exactly one terminal state wins
		r = newReq("ar_trans_00004")
		decisions := []Request{r, r, r}
		decisions[0].State, decisions[0].DecidedBy, decisions[0].ExpiresAt = StateApproved, approver.PublicId, exp
		decisions[1].State, decisions[1].DecidedBy = StateDenied, other.PublicId
		decisions[2].State, decisions[2].DecidedBy = StateCancelled, requester.PublicId
		errs := make([]error, len(decisions))
		var wg sync.WaitGroup
		for i := range decisions {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = repo.Update(ctx, decisions[i])
			}(i)
		}
		wg.Wait()
		wins := 0
		for _, e := range errs {
			if e == nil {
				wins++
			} else {
				require.ErrorIs(t, e, ErrVersionConflict)
			}
		}
		assert.Equal(t, 1, wins)
		final, err := repo.Get(ctx, r.Id)
		require.NoError(t, err)
		assert.True(t, final.State.Terminal() || final.State == StateApproved)
		assert.EqualValues(t, 2, final.Version)

		require.NoError(t, db.TestVerifyOplog(t, rw, "ar_trans_00001", db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(time.Minute)))
	})
	t.Run("short id rejected by the database", func(t *testing.T) {
		r := mk(t, "short", user.PublicId, t0)
		r.ScopeId = org.PublicId
		_, err := repo.Create(ctx, r)
		require.ErrorIs(t, err, ErrInvalidInput)
	})
}
