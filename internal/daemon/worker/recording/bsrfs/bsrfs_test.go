// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package bsrfs

import (
	"context"
	"io"
	"io/fs"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	bssh "github.com/hashicorp/boundary/internal/bsr/ssh"
	"github.com/hashicorp/boundary/internal/bsr/ssh/recorder"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sessionID   = "s_1234567890"
	recordingID = "sr_1234567890"
	connID      = "cr_1234567890"
	chanID      = "chr_1234567890"
)

func newFS(t *testing.T, quota, reserve int64) (*FS, *scratch.Store) {
	t.Helper()
	st, err := scratch.New(t.TempDir(), quota)
	require.NoError(t, err)
	require.NoError(t, st.Reserve(sessionID, reserve))
	f, err := New(st, sessionID)
	require.NoError(t, err)
	return f, st
}

func TestNew(t *testing.T) {
	_, err := New(nil, "s_1")
	require.Error(t, err)
	_, err = New(&scratch.Store{}, "")
	require.Error(t, err)
}

func TestFilesAndContainers(t *testing.T) {
	ctx := context.Background()
	f, st := newFS(t, 100, 10)
	root, err := f.New(ctx, "sr_1")
	require.NoError(t, err)
	_, err = f.New(ctx, "sr_1")
	require.ErrorIs(t, err, fs.ErrExist)
	_, err = f.Open(ctx, "sr_2")
	require.ErrorIs(t, err, fs.ErrNotExist)

	w, err := root.Create(ctx, "meta.txt")
	require.NoError(t, err)
	_, err = root.Create(ctx, "meta.txt")
	require.ErrorIs(t, err, fs.ErrExist)
	_, err = w.WriteString("hello")
	require.NoError(t, err)
	_, err = w.WriteAndClose([]byte(" world"))
	require.NoError(t, err)
	assert.Equal(t, int64(11), st.Used())
	require.Error(t, w.Close())

	_, err = root.SubContainer(ctx, "conn")
	require.ErrorIs(t, err, fs.ErrNotExist)
	sub, err := root.SubContainer(ctx, "conn", storage.WithCreateFile())
	require.NoError(t, err)
	sf, err := sub.OpenFile(ctx, "x", storage.WithCreateFile())
	require.NoError(t, err)
	require.NoError(t, sf.Close())

	reopened, err := f.Open(ctx, "sr_1")
	require.NoError(t, err)
	r, err := reopened.OpenFile(ctx, "meta.txt")
	require.NoError(t, err)
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(b))
	fi, err := r.Stat()
	require.NoError(t, err)
	assert.EqualValues(t, 11, fi.Size())
	_, err = r.(io.Writer).Write([]byte("x"))
	require.Error(t, err, "read-only file")
	require.NoError(t, r.Close())
	_, err = reopened.OpenFile(ctx, "missing")
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestConfinement(t *testing.T) {
	ctx := context.Background()
	f, _ := newFS(t, 100, 10)
	for _, name := range []string{"..", "../x", "/abs", "a/../../b", ""} {
		_, err := f.New(ctx, name)
		assert.ErrorIs(t, err, scratch.ErrInvalidFileName, name)
		_, err = f.Open(ctx, name)
		assert.ErrorIs(t, err, scratch.ErrInvalidFileName, name)
	}
	root, err := f.New(ctx, "sr_1")
	require.NoError(t, err)
	for _, name := range []string{"..", "../x", "/abs", "a/../b", "", "x/y/../../.."} {
		_, err = root.Create(ctx, name)
		assert.ErrorIs(t, err, scratch.ErrInvalidFileName, name)
		_, err = root.OpenFile(ctx, name)
		assert.ErrorIs(t, err, scratch.ErrInvalidFileName, name)
		_, err = root.SubContainer(ctx, name, storage.WithCreateFile())
		assert.ErrorIs(t, err, scratch.ErrInvalidFileName, name)
	}
}

func TestQuotaFailsClosed(t *testing.T) {
	ctx := context.Background()
	f, st := newFS(t, 8, 4)
	root, err := f.New(ctx, "sr_1")
	require.NoError(t, err)
	w, err := root.Create(ctx, "a")
	require.NoError(t, err)
	_, err = w.Write([]byte("12345678"))
	require.NoError(t, err)
	n, err := w.Write([]byte("9"))
	require.ErrorIs(t, err, scratch.ErrQuotaExceeded)
	assert.Zero(t, n)
	assert.EqualValues(t, 8, st.Used())
	// The recording is now incomplete: further writes keep failing.
	_, err = w.Write([]byte(""))
	require.ErrorIs(t, err, scratch.ErrIncomplete)
}

func TestBSRRoundTrip(t *testing.T) {
	ctx := context.Background()
	f, st := newFS(t, 10<<20, 1<<20)
	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sessionID)
	require.NoError(t, err)
	keyFn := func(kms.WrappedKeys) (kms.UnwrappedKeys, error) {
		return kms.UnwrappedKeys{BsrKey: keys.BsrKey, PrivKey: keys.PrivKey}, nil
	}
	sess, err := bsr.NewSession(ctx, &bsr.SessionRecordingMeta{Id: recordingID, Protocol: bssh.Protocol},
		bsr.TestSessionMeta(sessionID), f, keys, bsr.WithSupportsMultiplex(true))
	require.NoError(t, err)
	rec, err := recorder.NewRecorder(ctx, sess, connID)
	require.NoError(t, err)
	ch, err := rec.Channel("session", chanID)
	require.NoError(t, err)
	require.NoError(t, ch.WriteData(bsr.Inbound, []byte("ls -l\n")))
	require.NoError(t, ch.WriteData(bsr.Outbound, []byte("total 0\n")))
	require.NoError(t, ch.Close())
	require.NoError(t, rec.Close())
	require.NoError(t, sess.EncodeSummary(ctx, &bsr.BaseSessionSummary{Id: recordingID, ConnectionCount: 1}))
	require.NoError(t, sess.Close(ctx))
	assert.Positive(t, st.Used())

	v, err := bsr.Validate(ctx, recordingID, f, keyFn)
	require.NoError(t, err)
	require.True(t, v.Valid, "BSR must validate: %+v", v)
	opened, err := bsr.OpenSession(ctx, recordingID, f, keyFn)
	require.NoError(t, err)
	require.NoError(t, opened.Close(ctx))
}

func TestBSRQuotaPropagates(t *testing.T) {
	ctx := context.Background()
	f, _ := newFS(t, 4096, 0)
	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sessionID)
	require.NoError(t, err)
	sess, err := bsr.NewSession(ctx, &bsr.SessionRecordingMeta{Id: recordingID, Protocol: bssh.Protocol},
		bsr.TestSessionMeta(sessionID), f, keys, bsr.WithSupportsMultiplex(true))
	if err != nil {
		require.ErrorIs(t, err, scratch.ErrQuotaExceeded)
		return
	}
	rec, err := recorder.NewRecorder(ctx, sess, connID)
	if err != nil {
		require.ErrorIs(t, err, scratch.ErrQuotaExceeded)
		return
	}
	ch, err := rec.Channel("session", chanID)
	if err != nil {
		require.ErrorIs(t, err, scratch.ErrQuotaExceeded)
		return
	}
	var werr error
	for i := 0; i < 200 && werr == nil; i++ {
		werr = ch.WriteData(bsr.Outbound, make([]byte, 1024))
	}
	if werr == nil {
		werr = ch.Close()
	}
	require.ErrorIs(t, werr, scratch.ErrQuotaExceeded)
}
