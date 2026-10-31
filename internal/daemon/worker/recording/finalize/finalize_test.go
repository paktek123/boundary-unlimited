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

type fakeScratch struct {
	finishErr error
	markErr   error
	calls     []string
}

func (s *fakeScratch) Finish(id string) error {
	s.calls = append(s.calls, "finish")
	return s.finishErr
}

func (s *fakeScratch) Path(id string) (string, error) {
	s.calls = append(s.calls, "path")
	return "/scratch/" + id, nil
}

func (s *fakeScratch) MarkUploaded(id string) error {
	s.calls = append(s.calls, "markuploaded")
	return s.markErr
}

func (s *fakeScratch) Discard(id string) error {
	s.calls = append(s.calls, "discard")
	return scratch.ErrNotFound // already removed by MarkUploaded
}

type fakeSub struct {
	res  upload.Result
	recs []upload.Recording
}

func (s *fakeSub) Submit(_ context.Context, rec upload.Recording) upload.Result {
	s.recs = append(s.recs, rec)
	return s.res
}

func TestNew(t *testing.T) {
	_, err := New(nil, &fakeSub{})
	require.Error(t, err)
	_, err = New(&fakeScratch{}, nil)
	require.Error(t, err)
	_, err = New(&fakeScratch{}, &fakeSub{})
	require.NoError(t, err)
}

func TestFinalize(t *testing.T) {
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		sc, sub := &fakeScratch{}, &fakeSub{res: upload.Result{Status: upload.StatusUploaded, Attempts: 1}}
		f, _ := New(sc, sub)
		res, err := f.Finalize(ctx, "s_1")
		require.NoError(t, err)
		assert.Equal(t, upload.StatusUploaded, res.Status)
		assert.Equal(t, []upload.Recording{{SessionID: "s_1", Dir: "/scratch/s_1"}}, sub.recs)
		assert.Equal(t, []string{"finish", "path", "markuploaded", "discard"}, sc.calls)
	})
	t.Run("finish error fails closed", func(t *testing.T) {
		sc, sub := &fakeScratch{finishErr: scratch.ErrIncomplete}, &fakeSub{}
		f, _ := New(sc, sub)
		_, err := f.Finalize(ctx, "s_1")
		require.ErrorIs(t, err, scratch.ErrIncomplete)
		assert.Empty(t, sub.recs)
		assert.Equal(t, []string{"finish"}, sc.calls)
	})
	for name, status := range map[string]upload.Status{
		"pending":  upload.StatusPending,
		"invalid":  upload.StatusInvalid,
		"canceled": upload.StatusCanceled,
	} {
		t.Run("submit "+name+" keeps data", func(t *testing.T) {
			sc := &fakeScratch{}
			sub := &fakeSub{res: upload.Result{Status: status, Err: errors.New("boom")}}
			f, _ := New(sc, sub)
			res, err := f.Finalize(ctx, "s_1")
			require.Error(t, err)
			assert.Equal(t, status, res.Status)
			assert.NotContains(t, sc.calls, "markuploaded")
			assert.NotContains(t, sc.calls, "discard")
		})
	}
	t.Run("retry after failure uploads", func(t *testing.T) {
		sc := &fakeScratch{}
		sub := &fakeSub{res: upload.Result{Status: upload.StatusPending, Err: errors.New("boom")}}
		f, _ := New(sc, sub)
		_, err := f.Finalize(ctx, "s_1")
		require.Error(t, err)
		sub.res = upload.Result{Status: upload.StatusUploaded}
		_, err = f.Finalize(ctx, "s_1")
		require.NoError(t, err)
		assert.Len(t, sub.recs, 2)
	})
	t.Run("mark uploaded error is returned and not cached", func(t *testing.T) {
		sc := &fakeScratch{markErr: errors.New("disk")}
		sub := &fakeSub{res: upload.Result{Status: upload.StatusUploaded}}
		f, _ := New(sc, sub)
		_, err := f.Finalize(ctx, "s_1")
		require.Error(t, err)
		assert.NotContains(t, sc.calls, "discard")
	})
	t.Run("idempotent", func(t *testing.T) {
		sc, sub := &fakeScratch{}, &fakeSub{res: upload.Result{Status: upload.StatusUploaded}}
		f, _ := New(sc, sub)
		_, err := f.Finalize(ctx, "s_1")
		require.NoError(t, err)
		_, err = f.Finalize(ctx, "s_1")
		require.NoError(t, err)
		assert.Len(t, sub.recs, 1)
	})
}

// TestFinalizeRealScratch checks the pipeline against the real scratch store.
func TestFinalizeRealScratch(t *testing.T) {
	ctx := context.Background()
	st, err := scratch.New(t.TempDir(), 1024)
	require.NoError(t, err)
	require.NoError(t, st.Reserve("s_1", 100))
	_, err = st.Write("s_1", []byte("data"))
	require.NoError(t, err)
	f, _ := New(st, &fakeSub{res: upload.Result{Status: upload.StatusUploaded}})
	_, err = f.Finalize(ctx, "s_1")
	require.NoError(t, err)
	assert.Zero(t, st.Used())

	// An incomplete recording is never finalised or discarded.
	require.NoError(t, st.Reserve("s_2", 1))
	_, err = st.Write("s_2", make([]byte, 2000))
	require.ErrorIs(t, err, scratch.ErrQuotaExceeded)
	sub := &fakeSub{}
	f, _ = New(st, sub)
	_, err = f.Finalize(ctx, "s_2")
	require.ErrorIs(t, err, scratch.ErrIncomplete)
	assert.Empty(t, sub.recs)
	_, err = st.Path("s_2")
	require.NoError(t, err)
}
