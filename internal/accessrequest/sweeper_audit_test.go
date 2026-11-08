// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package accessrequest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type panicEmitter struct{}

func (panicEmitter) Emit(context.Context, Event) error { panic("canary-justification-text") }

// failOnce fails for one request id and records the others.
type failFor struct {
	id  string
	rec RecordingEmitter
}

func (f *failFor) Emit(ctx context.Context, e Event) error {
	if e.RequestId == f.id {
		return errors.New("sink down")
	}
	return f.rec.Emit(ctx, e)
}

func TestSweeperAuditsExpiry(t *testing.T) {
	ctx := context.Background()
	repo := NewMemRepository()
	seed(t, repo)
	em := &RecordingEmitter{}
	s, err := NewSweeper(repo, em)
	require.NoError(t, err)
	now := t0.Add(DefaultMaxPendingAge)

	res, err := s.Run(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, SweepResult{Expired: 2}, res)
	evs := em.Events()
	require.Len(t, evs, 2)
	ids := map[string]bool{}
	for _, e := range evs {
		assert.Equal(t, EventExpire, e.Type)
		assert.True(t, e.At.Equal(now))
		ids[e.RequestId] = true
	}
	assert.Equal(t, map[string]bool{"pending-old": true, "appr": true}, ids)

	// Idempotent: already expired, denied, cancelled and revoked requests emit nothing.
	res, err = s.Run(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, SweepResult{}, res)
	assert.Len(t, em.Events(), 2)
	for _, id := range []string{"denied", "cancelled", "revoked"} {
		for _, e := range em.Events() {
			assert.NotEqual(t, id, e.RequestId)
		}
	}
}

func TestSweeperEmitFailureLeavesStateUnchanged(t *testing.T) {
	ctx := context.Background()
	repo := NewMemRepository()
	seed(t, repo)
	em := &failFor{id: "appr"}
	s, err := NewSweeper(repo, em)
	require.NoError(t, err)

	res, err := s.Run(ctx, t0.Add(DefaultMaxPendingAge))
	require.Error(t, err)
	assert.ErrorIs(t, err, errSweepAudit)
	assert.Equal(t, SweepResult{Expired: 1}, res)
	assert.Equal(t, StateApproved, stateOf(t, repo, "appr"), "audit failed: state must not change")
	assert.Equal(t, StateExpired, stateOf(t, repo, "pending-old"), "others still processed")
	assert.NotContains(t, err.Error(), "sink down")

	// Once the sink recovers the request is expired.
	s2, err := NewSweeper(repo, &RecordingEmitter{})
	require.NoError(t, err)
	_, err = s2.Run(ctx, t0.Add(DefaultMaxPendingAge))
	require.NoError(t, err)
	assert.Equal(t, StateExpired, stateOf(t, repo, "appr"))
}

func TestSweeperEmitPanicRecovered(t *testing.T) {
	repo := NewMemRepository()
	seed(t, repo)
	s, err := NewSweeper(repo, panicEmitter{})
	require.NoError(t, err)
	res, err := s.Run(context.Background(), t0.Add(DefaultMaxPendingAge))
	require.ErrorIs(t, err, errSweepAudit)
	assert.Equal(t, SweepResult{}, res)
	assert.Equal(t, StatePending, stateOf(t, repo, "pending-old"))
	assert.Equal(t, StateApproved, stateOf(t, repo, "appr"))
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", err, err, err), "canary-justification-text")
}

func TestSweeperRequiresEmitter(t *testing.T) {
	repo := NewMemRepository()
	_, err := NewSweeper(repo, nil)
	require.ErrorIs(t, err, ErrInvalidInput)
	var typedNil *RecordingEmitter
	_, err = NewSweeper(repo, typedNil)
	require.ErrorIs(t, err, ErrInvalidInput)
	_, err = NewSweeper(nil, &RecordingEmitter{})
	require.ErrorIs(t, err, ErrInvalidInput)
	_, err = NewSweeper(repo, nil, WithoutAudit())
	require.NoError(t, err)

	// A literal Sweeper with no emitter fails closed in Run.
	seed(t, repo)
	_, err = (&Sweeper{Repo: repo}).Run(context.Background(), t0.Add(DefaultMaxPendingAge))
	require.ErrorIs(t, err, ErrInvalidInput)
	assert.Equal(t, StatePending, stateOf(t, repo, "pending-old"))
}

func TestSweeperEventsCarryNoJustification(t *testing.T) {
	repo := NewMemRepository()
	r := mk(t, "j1", "u1", t0)
	r.Justification = "canary-justification-text"
	_, err := repo.Create(context.Background(), r)
	require.NoError(t, err)
	em := &RecordingEmitter{}
	s, err := NewSweeper(repo, em)
	require.NoError(t, err)
	_, err = s.Run(context.Background(), t0.Add(DefaultMaxPendingAge))
	require.NoError(t, err)
	require.Len(t, em.Events(), 1)
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", em.Events()[0], em.Events()[0], em.Events()[0]), "canary-justification-text")
}
