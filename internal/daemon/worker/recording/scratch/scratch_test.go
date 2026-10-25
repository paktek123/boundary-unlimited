// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package scratch

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newStore(t *testing.T, quota int64) (*Store, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "scratch")
	s, err := New(root, quota)
	require.NoError(t, err)
	return s, root
}

func TestNew(t *testing.T) {
	s, root := newStore(t, 10)
	require.NotNil(t, s)
	fi, err := os.Stat(root)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm())

	_, err = New("", 10)
	assert.Error(t, err)
	_, err = New(root, 0)
	assert.Error(t, err)
}

func TestReserve(t *testing.T) {
	s, root := newStore(t, 100)
	require.NoError(t, s.Reserve("s_1", 60))
	assert.Equal(t, int64(60), s.Used())
	assert.ErrorIs(t, s.Reserve("s_2", 41), ErrQuotaExceeded)
	_, err := os.Stat(filepath.Join(root, "s_2"))
	assert.True(t, os.IsNotExist(err), "failed reserve must leave nothing behind")
	require.NoError(t, s.Reserve("s_2", 40), "exact boundary is allowed")
	assert.ErrorIs(t, s.Reserve("s_1", 0), ErrExists)

	fi, err := os.Stat(filepath.Join(root, "s_1", "data"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestWriteQuota(t *testing.T) {
	s, root := newStore(t, 10)
	require.NoError(t, s.Reserve("s_1", 4))
	n, err := s.Write("s_1", []byte("abcd")) // consumes reservation
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, int64(4), s.Used())
	n, err = s.Write("s_1", []byte("123456")) // boundary: total 10
	require.NoError(t, err)
	assert.Equal(t, 6, n)
	assert.Equal(t, int64(10), s.Used())

	n, err = s.Write("s_1", []byte("x"))
	assert.ErrorIs(t, err, ErrQuotaExceeded)
	assert.Equal(t, 0, n)
	_, err = os.Stat(filepath.Join(root, "s_1", "incomplete"))
	assert.NoError(t, err, "quota failure marks the recording incomplete")
	b, err := os.ReadFile(filepath.Join(root, "s_1", "data"))
	require.NoError(t, err)
	assert.Equal(t, "abcd123456", string(b), "no partial or dropped writes")

	_, err = s.Write("s_1", []byte("y"))
	assert.ErrorIs(t, err, ErrIncomplete, "no further writes after incomplete")
	assert.ErrorIs(t, s.Finish("s_1"), ErrIncomplete)
}

func TestLifecycle(t *testing.T) {
	s, root := newStore(t, 100)
	require.NoError(t, s.Reserve("s_1", 50))
	_, err := s.Write("s_1", []byte("hello"))
	require.NoError(t, err)

	assert.ErrorIs(t, s.MarkUploaded("s_1"), ErrNotFinished)
	require.NoError(t, s.Finish("s_1"))
	assert.Equal(t, int64(5), s.Used(), "unused reservation released")
	_, err = s.Write("s_1", []byte("x"))
	assert.Error(t, err)

	_, err = os.Stat(filepath.Join(root, "s_1"))
	require.NoError(t, err, "files kept until upload verified")
	require.NoError(t, s.MarkUploaded("s_1"))
	_, err = os.Stat(filepath.Join(root, "s_1"))
	assert.True(t, os.IsNotExist(err))
	assert.Equal(t, int64(0), s.Used())
	assert.ErrorIs(t, s.MarkUploaded("s_1"), ErrNotFound)
}

func TestDiscard(t *testing.T) {
	s, root := newStore(t, 100)
	require.NoError(t, s.Reserve("s_1", 10))
	_, err := s.Write("s_1", []byte("abc"))
	require.NoError(t, err)
	require.NoError(t, s.Discard("s_1"))
	_, err = os.Stat(filepath.Join(root, "s_1"))
	assert.True(t, os.IsNotExist(err))
	assert.Equal(t, int64(0), s.Used())
	assert.ErrorIs(t, s.Discard("s_1"), ErrNotFound)
}

func TestInvalidSessionIDs(t *testing.T) {
	s, root := newStore(t, 100)
	outside := filepath.Join(filepath.Dir(root), "evil")
	for _, id := range []string{"", "..", ".", "../evil", "a/b", `a\b`, "s_1/..", "/abs", "a\x00b", "a b", "s-1"} {
		assert.ErrorIs(t, s.Reserve(id, 1), ErrInvalidSessionID, "%q", id)
		_, err := s.Write(id, []byte("x"))
		assert.ErrorIs(t, err, ErrInvalidSessionID, "%q", id)
		assert.ErrorIs(t, s.Finish(id), ErrInvalidSessionID, "%q", id)
		assert.ErrorIs(t, s.MarkUploaded(id), ErrInvalidSessionID, "%q", id)
		assert.ErrorIs(t, s.Discard(id), ErrInvalidSessionID, "%q", id)
		_, err = s.Path(id)
		assert.ErrorIs(t, err, ErrInvalidSessionID, "%q", id)
	}
	_, err := os.Stat(outside)
	assert.True(t, os.IsNotExist(err))
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestConcurrentWriters(t *testing.T) {
	const writers, perWriter, chunk = 8, 50, 10
	s, _ := newStore(t, writers*perWriter*chunk)
	for i := 0; i < writers; i++ {
		require.NoError(t, s.Reserve(string(rune('a'+i))+"_x", 0))
	}
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		id := string(rune('a'+i)) + "_x"
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				_, err := s.Write(id, []byte("0123456789"))
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(writers*perWriter*chunk), s.Used())

	// The store is exactly full: any further write fails closed.
	_, err := s.Write("a_x", []byte("z"))
	assert.ErrorIs(t, err, ErrQuotaExceeded)
}

func TestConcurrentQuotaNeverExceeded(t *testing.T) {
	const quota = 100
	s, _ := newStore(t, quota)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		id := string(rune('a'+i)) + "_x"
		require.NoError(t, s.Reserve(id, 0))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, _ = s.Write(id, []byte("0123456789"))
			}
		}()
	}
	wg.Wait()
	assert.LessOrEqual(t, s.Used(), int64(quota))
}

func TestRecover(t *testing.T) {
	s, root := newStore(t, 100)
	require.NoError(t, s.Reserve("s_active", 0))
	_, err := s.Write("s_active", []byte("12345"))
	require.NoError(t, err)
	require.NoError(t, s.Reserve("s_done", 0))
	_, err = s.Write("s_done", []byte("abc"))
	require.NoError(t, err)
	require.NoError(t, s.Finish("s_done"))
	require.NoError(t, os.Mkdir(filepath.Join(root, "bad.name"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "afile"), nil, 0o600))

	// Simulate restart with a new Store over the same root.
	s2, err := New(root, 100)
	require.NoError(t, err)
	orphans, err := s2.Recover()
	require.NoError(t, err)
	assert.Equal(t, []Orphan{
		{SessionID: "s_active", Size: 5, Finished: false},
		{SessionID: "s_done", Size: 3, Finished: true},
	}, orphans)
	assert.Equal(t, int64(8), s2.Used())

	_, err = os.Stat(filepath.Join(root, "s_active", "incomplete"))
	assert.NoError(t, err, "unfinished orphan marked incomplete")
	_, err = os.Stat(filepath.Join(root, "s_done", "incomplete"))
	assert.True(t, os.IsNotExist(err), "finished orphan not marked incomplete")
	for _, id := range []string{"s_active", "s_done", "bad.name"} {
		_, err = os.Stat(filepath.Join(root, id))
		assert.NoError(t, err, "recover never deletes: %s", id)
	}

	_, err = s2.Write("s_active", []byte("x"))
	assert.ErrorIs(t, err, ErrIncomplete)
	require.NoError(t, s2.MarkUploaded("s_done"))

	again, err := s2.Recover()
	require.NoError(t, err)
	assert.Len(t, again, 0, "already registered recordings are not re-reported")
}

func TestFinishFailsWhenDataFileMissing(t *testing.T) {
	root := t.TempDir()
	s, err := New(root, 1<<20)
	require.NoError(t, err)
	require.NoError(t, s.Reserve("s_sync", 10))
	d, err := s.dir("s_sync")
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(d, dataFile)))
	// Finish must not mark a recording finished when its data cannot be synced.
	require.Error(t, s.Finish("s_sync"))
	_, statErr := os.Lstat(filepath.Join(d, finishedFile))
	require.True(t, os.IsNotExist(statErr))
}
