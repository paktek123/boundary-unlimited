// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package accessrequest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mk(t *testing.T, id, requester string, at time.Time) Request {
	t.Helper()
	r, err := New(fakeClock{at}, id, requester, "p_1", []string{"g"}, "why", time.Hour)
	require.NoError(t, err)
	return r
}

func TestMemRepositoryCRUD(t *testing.T) {
	ctx := context.Background()
	repo := NewMemRepository()
	r, err := repo.Create(ctx, mk(t, "a", "u1", t0))
	require.NoError(t, err)
	assert.EqualValues(t, 1, r.Version)

	_, err = repo.Create(ctx, mk(t, "a", "u1", t0))
	require.ErrorIs(t, err, ErrAlreadyExists)
	bad := mk(t, "b", "u1", t0)
	bad.Version = 3
	_, err = repo.Create(ctx, bad)
	require.ErrorIs(t, err, ErrInvalidInput)

	_, err = repo.Get(ctx, "nope")
	require.ErrorIs(t, err, ErrNotFound)

	// returned values are copies
	r.Grants[0] = "mutated"
	got, err := repo.Get(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, "g", got.Grants[0])

	_, err = repo.Update(ctx, Request{Id: "nope"})
	require.ErrorIs(t, err, ErrNotFound)
}

func TestMemRepositoryListFilters(t *testing.T) {
	ctx := context.Background()
	repo := NewMemRepository()
	for i, u := range []string{"u1", "u2", "u1"} {
		_, err := repo.Create(ctx, mk(t, fmt.Sprintf("r%d", i), u, t0.Add(time.Duration(i)*time.Minute)))
		require.NoError(t, err)
	}
	cur, err := repo.Get(ctx, "r0")
	require.NoError(t, err)
	appr, err := Approve(cur, "boss", t0)
	require.NoError(t, err)
	_, err = repo.Update(ctx, appr)
	require.NoError(t, err)

	ids := func(f ListFilter) []string {
		l, err := repo.List(ctx, f)
		require.NoError(t, err)
		var out []string
		for _, r := range l {
			out = append(out, r.Id)
		}
		return out
	}
	assert.Equal(t, []string{"r0", "r1", "r2"}, ids(ListFilter{}))
	assert.Equal(t, []string{"r0", "r2"}, ids(ListFilter{RequesterId: "u1"}))
	assert.Equal(t, []string{"r0"}, ids(ListFilter{ApproverId: "boss"}))
	assert.Equal(t, []string{"r1", "r2"}, ids(ListFilter{States: []State{StatePending}}))
	assert.Equal(t, []string{"r0"}, ids(ListFilter{States: []State{StateApproved, StatePending}, RequesterId: "u1", ApproverId: "boss"}))
	assert.Empty(t, ids(ListFilter{States: []State{StateDenied}}))
}

func TestMemRepositoryUpdateConflict(t *testing.T) {
	ctx := context.Background()
	repo := NewMemRepository()
	r, err := repo.Create(ctx, mk(t, "a", "u1", t0))
	require.NoError(t, err)
	a, err := Approve(r, "boss", t0)
	require.NoError(t, err)
	u, err := repo.Update(ctx, a)
	require.NoError(t, err)
	assert.EqualValues(t, 2, u.Version)
	// stale version loses
	d, err := Deny(r, "boss2", t0)
	require.NoError(t, err)
	_, err = repo.Update(ctx, d)
	require.ErrorIs(t, err, ErrVersionConflict)
	got, _ := repo.Get(ctx, "a")
	assert.Equal(t, StateApproved, got.State)
}

func TestMemRepositoryConcurrentUpdate(t *testing.T) {
	ctx := context.Background()
	repo := NewMemRepository()
	r, err := repo.Create(ctx, mk(t, "a", "u1", t0))
	require.NoError(t, err)
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, err := Approve(r, fmt.Sprintf("boss%d", i), t0)
			if err != nil {
				t.Error(err)
				return
			}
			_, err = repo.Update(ctx, a)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrVersionConflict):
				conflicts.Add(1)
			default:
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	assert.EqualValues(t, 1, wins.Load())
	assert.EqualValues(t, 19, conflicts.Load())
}

func TestMemRepositoryContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	repo := NewMemRepository()
	_, err := repo.Create(ctx, mk(t, "a", "u1", t0))
	require.ErrorIs(t, err, context.Canceled)
	_, err = repo.Get(ctx, "a")
	require.ErrorIs(t, err, context.Canceled)
	_, err = repo.List(ctx, ListFilter{})
	require.ErrorIs(t, err, context.Canceled)
	_, err = repo.Update(ctx, Request{})
	require.ErrorIs(t, err, context.Canceled)
}

func seed(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	for _, id := range []string{"pending-old", "pending-new", "appr", "denied", "cancelled", "revoked"} {
		at := t0
		if id == "pending-new" {
			at = t0.Add(DefaultMaxPendingAge)
		}
		_, err := repo.Create(ctx, mk(t, id, "u1", at))
		require.NoError(t, err)
	}
	step := func(id string, f func(Request) (Request, error)) {
		r, err := repo.Get(ctx, id)
		require.NoError(t, err)
		n, err := f(r)
		require.NoError(t, err)
		_, err = repo.Update(ctx, n)
		require.NoError(t, err)
	}
	step("appr", func(r Request) (Request, error) { return Approve(r, "b", t0) })
	step("denied", func(r Request) (Request, error) { return Deny(r, "b", t0) })
	step("cancelled", func(r Request) (Request, error) { return Cancel(r, "u1", t0) })
	step("revoked", func(r Request) (Request, error) {
		a, err := Approve(r, "b", t0)
		if err != nil {
			return a, err
		}
		return Revoke(a, "b", t0)
	})
}

func stateOf(t *testing.T, repo Repository, id string) State {
	t.Helper()
	r, err := repo.Get(context.Background(), id)
	require.NoError(t, err)
	return r.State
}

func TestSweeper(t *testing.T) {
	ctx := context.Background()
	repo := NewMemRepository()
	seed(t, repo)
	s := &Sweeper{Repo: repo}
	now := t0.Add(DefaultMaxPendingAge) // pending-old due; appr (1h) due; pending-new created now
	res, err := s.Run(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, SweepResult{Expired: 2}, res)
	assert.Equal(t, StateExpired, stateOf(t, repo, "pending-old"))
	assert.Equal(t, StateExpired, stateOf(t, repo, "appr"))
	assert.Equal(t, StatePending, stateOf(t, repo, "pending-new"))
	assert.Equal(t, StateDenied, stateOf(t, repo, "denied"))
	assert.Equal(t, StateCancelled, stateOf(t, repo, "cancelled"))
	assert.Equal(t, StateRevoked, stateOf(t, repo, "revoked"))

	// idempotent
	res, err = s.Run(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, SweepResult{}, res)

	// nothing due before deadlines
	repo2 := NewMemRepository()
	seed(t, repo2)
	res, err = (&Sweeper{Repo: repo2}).Run(ctx, t0.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, SweepResult{}, res)
}

func TestSweeperInvalid(t *testing.T) {
	_, err := (&Sweeper{}).Run(context.Background(), t0)
	require.ErrorIs(t, err, ErrInvalidInput)
	_, err = (&Sweeper{Repo: NewMemRepository()}).Run(context.Background(), time.Time{})
	require.ErrorIs(t, err, ErrInvalidInput)
	var nilS *Sweeper
	_, err = nilS.Run(context.Background(), t0)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestSweeperContextCancelled(t *testing.T) {
	repo := NewMemRepository()
	seed(t, repo)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&Sweeper{Repo: repo}).Run(ctx, t0.Add(100*time.Hour))
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, StatePending, stateOf(t, repo, "pending-old"))
}

// conflictRepo makes the first n Updates fail with a version conflict.
type conflictRepo struct {
	*MemRepository
	mu sync.Mutex
	n  int
}

func (c *conflictRepo) Update(ctx context.Context, r Request) (Request, error) {
	c.mu.Lock()
	if c.n > 0 {
		c.n--
		c.mu.Unlock()
		return Request{}, ErrVersionConflict
	}
	c.mu.Unlock()
	return c.MemRepository.Update(ctx, r)
}

func TestSweeperConflictRetriedOnceThenSkipped(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		fails  int
		want   SweepResult
		wantSt State
	}{
		{"one conflict retried", 1, SweepResult{Expired: 1}, StateExpired},
		{"two conflicts skipped", 2, SweepResult{Skipped: 1}, StatePending},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := NewMemRepository()
			_, err := mem.Create(ctx, mk(t, "a", "u1", t0))
			require.NoError(t, err)
			res, err := (&Sweeper{Repo: &conflictRepo{MemRepository: mem, n: tc.fails}}).Run(ctx, t0.Add(100*time.Hour))
			require.NoError(t, err)
			assert.Equal(t, tc.want, res)
			assert.Equal(t, tc.wantSt, stateOf(t, mem, "a"))
		})
	}
}

func TestSweeperConcurrent(t *testing.T) {
	ctx := context.Background()
	repo := NewMemRepository()
	seed(t, repo)
	now := t0.Add(100 * time.Hour)
	var total atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := (&Sweeper{Repo: repo}).Run(ctx, now)
			if err != nil {
				t.Error(err)
			}
			total.Add(int32(res.Expired))
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 3, total.Load(), "each due request expires exactly once")
	assert.Equal(t, StateDenied, stateOf(t, repo, "denied"))
}
