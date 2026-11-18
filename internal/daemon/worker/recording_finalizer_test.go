// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const canaryCred = "CANARY-BUCKET-SECRET-0123456789"

type memScratch struct {
	dir                         string
	finished, marked, discarded bool
}

func (s *memScratch) Finish(string) error         { s.finished = true; return nil }
func (s *memScratch) Path(string) (string, error) { return s.dir, nil }
func (s *memScratch) MarkUploaded(string) error   { s.marked = true; return nil }
func (s *memScratch) Discard(string) error        { s.discarded = true; return nil }

type memBucket struct {
	files   map[string][]byte
	failPut bool
	openErr error
	closed  bool
}

func (b *memBucket) Open(context.Context, string) (RecordingBucketSession, error) {
	if b.openErr != nil {
		return nil, b.openErr
	}
	return b, nil
}
func (b *memBucket) Put(_ context.Context, rel string, r io.Reader) error {
	if b.failPut {
		return errors.New("put failed " + canaryCred)
	}
	data, _ := io.ReadAll(r)
	b.files[rel] = data
	return nil
}
func (b *memBucket) Close() error { b.closed = true; return nil }

type okValidator struct{ err error }

func (v okValidator) Validate(context.Context, upload.Recording) error { return v.err }

type noSleep struct{}

func (noSleep) Sleep(context.Context, time.Duration) error { return nil }

type nopEvents struct{ evs []upload.Event }

func (n *nopEvents) Emit(e upload.Event) { n.evs = append(n.evs, e) }

func newFin(t *testing.T, sc *memScratch, b *memBucket, val upload.Validator, ev *nopEvents) (res upload.Result, err error) {
	t.Helper()
	f, e := newRecordingFinalizer(recordingFinalizerDeps{
		Scratch: sc, Buckets: b, Validator: val, Clock: noSleep{}, Events: ev,
		Options: upload.Options{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})
	require.NoError(t, e)
	return f.Finalize(context.Background(), "s_1234567890")
}

func recDir(t *testing.T) string {
	d := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(d, "sub"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(d, "a.meta"), []byte("a"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(d, "sub", "b.data"), []byte("b"), 0o600))
	return d
}

func TestFinalizerUploadsAfterValidationAndDiscardsScratch(t *testing.T) {
	sc, b, ev := &memScratch{dir: recDir(t)}, &memBucket{files: map[string][]byte{}}, &nopEvents{}
	res, err := newFin(t, sc, b, okValidator{}, ev)
	require.NoError(t, err)
	assert.Equal(t, upload.StatusUploaded, res.Status)
	assert.Equal(t, map[string][]byte{"a.meta": []byte("a"), "sub/b.data": []byte("b")}, b.files)
	assert.True(t, b.closed)
	assert.True(t, sc.marked && sc.discarded)
}

func TestFinalizerUploadFailureKeepsScratch(t *testing.T) {
	sc, b, ev := &memScratch{dir: recDir(t)}, &memBucket{files: map[string][]byte{}, failPut: true}, &nopEvents{}
	res, err := newFin(t, sc, b, okValidator{}, ev)
	require.Error(t, err)
	assert.NotEqual(t, upload.StatusUploaded, res.Status)
	assert.False(t, sc.marked || sc.discarded, "scratch must be kept")
	assert.True(t, b.closed)
	assert.NotContains(t, err.Error(), canaryCred)
	for _, e := range ev.evs {
		if e.Err != nil {
			assert.NotContains(t, e.Err.Error(), canaryCred)
		}
	}
}

func TestFinalizerBucketUnavailableKeepsScratch(t *testing.T) {
	sc, b := &memScratch{dir: recDir(t)}, &memBucket{files: map[string][]byte{}, openErr: errors.New(canaryCred)}
	_, err := newFin(t, sc, b, okValidator{}, &nopEvents{})
	require.Error(t, err)
	assert.False(t, sc.marked || sc.discarded)
	assert.NotContains(t, err.Error(), canaryCred)
}

func TestFinalizerValidationFailureBlocksUpload(t *testing.T) {
	sc, b := &memScratch{dir: recDir(t)}, &memBucket{files: map[string][]byte{}}
	res, err := newFin(t, sc, b, okValidator{err: ErrRecordingValidation}, &nopEvents{})
	require.Error(t, err)
	assert.Equal(t, upload.StatusInvalid, res.Status)
	assert.Empty(t, b.files)
	assert.False(t, sc.marked || sc.discarded)
}

func TestStorageUploaderRejectsSymlinks(t *testing.T) {
	d := recDir(t)
	require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(d, "link")))
	b := &memBucket{files: map[string][]byte{}}
	err := storageUploader{src: b}.Upload(context.Background(), upload.Recording{SessionID: "s_1", Dir: d})
	require.ErrorIs(t, err, ErrRecordingUpload)
	assert.NotContains(t, err.Error(), "passwd")
	assert.NotContains(t, string(bytes.Join(valuesOf(b.files), nil)), "root:")
}

func valuesOf(m map[string][]byte) [][]byte {
	var out [][]byte
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestNewRecordingFinalizerFailsClosed(t *testing.T) {
	_, err := newRecordingFinalizer(recordingFinalizerDeps{})
	require.ErrorIs(t, err, ErrRecordingUpload)
	_, err = newRecordingFinalizer(recordingFinalizerDeps{Buckets: &memBucket{}})
	require.ErrorIs(t, err, ErrRecordingUpload)
}
