// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package finalize

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRecoverer struct {
	orphans []scratch.Orphan
	err     error
}

func (r *fakeRecoverer) Recover() ([]scratch.Orphan, error) { return r.orphans, r.err }

type fakeRunner struct {
	failIDs map[string]error
	ids     []string
	onCall  func()
}

func (r *fakeRunner) Finalize(_ context.Context, id string) (upload.Result, error) {
	r.ids = append(r.ids, id)
	if r.onCall != nil {
		r.onCall()
	}
	return upload.Result{}, r.failIDs[id]
}

func TestRecover(t *testing.T) {
	orphans := []scratch.Orphan{{SessionID: "s_1"}, {SessionID: "s_2"}, {SessionID: "s_3"}}
	t.Run("nil collaborators", func(t *testing.T) {
		require.Error(t, Recover(context.Background(), nil, &fakeRunner{}))
		require.Error(t, Recover(context.Background(), &fakeRecoverer{}, nil))
	})
	t.Run("no orphans", func(t *testing.T) {
		r := &fakeRunner{}
		require.NoError(t, Recover(context.Background(), &fakeRecoverer{}, r))
		assert.Empty(t, r.ids)
	})
	t.Run("recover error", func(t *testing.T) {
		boom := errors.New("boom")
		err := Recover(context.Background(), &fakeRecoverer{err: boom}, &fakeRunner{})
		require.ErrorIs(t, err, boom)
	})
	t.Run("multiple orphans", func(t *testing.T) {
		r := &fakeRunner{}
		require.NoError(t, Recover(context.Background(), &fakeRecoverer{orphans: orphans}, r))
		assert.Equal(t, []string{"s_1", "s_2", "s_3"}, r.ids)
	})
	t.Run("one failing does not stop others", func(t *testing.T) {
		r := &fakeRunner{failIDs: map[string]error{"s_1": scratch.ErrIncomplete, "s_3": errors.New("up")}}
		err := Recover(context.Background(), &fakeRecoverer{orphans: orphans}, r)
		require.Error(t, err)
		require.ErrorIs(t, err, scratch.ErrIncomplete)
		assert.Contains(t, err.Error(), "s_3")
		assert.Equal(t, []string{"s_1", "s_2", "s_3"}, r.ids)
	})
	t.Run("cancellation stops promptly", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		r := &fakeRunner{onCall: cancel}
		err := Recover(ctx, &fakeRecoverer{orphans: orphans}, r)
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, []string{"s_1"}, r.ids)
	})
}

// TestRecoverRealScratch checks that unfinished orphans are marked incomplete
// and kept, while finished ones are uploaded and removed.
func TestRecoverRealScratch(t *testing.T) {
	root := t.TempDir()
	old, err := scratch.New(root, 1024)
	require.NoError(t, err)
	require.NoError(t, old.Reserve("s_done", 10))
	_, err = old.Write("s_done", []byte("x"))
	require.NoError(t, err)
	require.NoError(t, old.Finish("s_done"))
	require.NoError(t, old.Reserve("s_crashed", 10))

	st, err := scratch.New(root, 1024)
	require.NoError(t, err)
	sub := &fakeSub{res: upload.Result{Status: upload.StatusUploaded}}
	f, _ := New(st, sub)
	err = Recover(context.Background(), st, f)
	require.ErrorIs(t, err, scratch.ErrIncomplete)
	require.Len(t, sub.recs, 1)
	assert.Equal(t, "s_done", sub.recs[0].SessionID)
	_, err = st.Path("s_crashed")
	require.NoError(t, err, "incomplete orphan must be kept")
	_, err = st.Path("s_done")
	require.ErrorIs(t, err, scratch.ErrNotFound)
}
