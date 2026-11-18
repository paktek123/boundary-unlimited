// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	bsrssh "github.com/hashicorp/boundary/internal/bsr/ssh"
	"github.com/hashicorp/boundary/internal/bsr/ssh/recorder"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/bsrfs"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
	"github.com/hashicorp/boundary/internal/storage"
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

// writeRealBSR records an empty-but-valid BSR session into a real scratch
// store, writes the session summary and finishes it, so bsrValidator runs against the production adapter.
func writeRealBSR(t *testing.T, sid string) (*scratch.Store, *kms.Keys) {
	t.Helper()
	ctx := context.Background()
	store, err := scratch.New(t.TempDir(), 8<<20)
	require.NoError(t, err)
	require.NoError(t, store.Reserve(sid, 4<<20))
	fs, err := bsrfs.New(store, sid)
	require.NoError(t, err)
	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sid)
	require.NoError(t, err)
	sess, err := bsr.NewSession(ctx, bsr.TestSessionRecordingMeta(sid, bsrssh.Protocol), bsr.TestSessionMeta(sid), fs, keys, bsr.WithSupportsMultiplex(true))
	require.NoError(t, err)
	rec, err := recorder.NewRecorder(ctx, sess, "cr_1234567890")
	require.NoError(t, err)
	require.NoError(t, rec.Close())
	require.NoError(t, sess.EncodeSummary(ctx, &bsr.BaseSessionSummary{Id: sid, ConnectionCount: 1}))
	require.NoError(t, sess.Close(ctx))
	require.NoError(t, store.Finish(sid))
	return store, keys
}

func unwrapWith(keys *kms.Keys) kms.KeyUnwrapCallbackFunc {
	return func(kms.WrappedKeys) (kms.UnwrappedKeys, error) {
		return kms.UnwrappedKeys{BsrKey: keys.BsrKey, PrivKey: keys.PrivKey}, nil
	}
}

func TestBSRValidator(t *testing.T) {
	ctx := context.Background()
	const sid = "s_1234567890"
	store, keys := writeRealBSR(t, sid)
	dir, err := store.Path(sid)
	require.NoError(t, err)
	rec := upload.Recording{SessionID: sid, Dir: dir}
	realFS := func(upload.Recording) (storage.FS, error) { return bsrfs.New(store, sid) }

	t.Run("openFS error", func(t *testing.T) {
		v := bsrValidator{openFS: func(upload.Recording) (storage.FS, error) { return nil, errors.New("boom " + canaryCred) }, unwrap: unwrapWith(keys)}
		err := v.Validate(ctx, rec)
		require.ErrorIs(t, err, ErrRecordingValidation)
		assert.NotContains(t, err.Error(), canaryCred)
	})
	t.Run("nil fs without error", func(t *testing.T) {
		v := bsrValidator{openFS: func(upload.Recording) (storage.FS, error) { return nil, nil }, unwrap: unwrapWith(keys)}
		require.ErrorIs(t, v.Validate(ctx, rec), ErrRecordingValidation)
	})
	t.Run("missing recording id", func(t *testing.T) {
		require.ErrorIs(t, bsrValidator{openFS: realFS, unwrap: unwrapWith(keys)}.Validate(ctx, upload.Recording{Dir: dir}), ErrRecordingValidation)
	})
}

// tamper appends a byte to the first regular file in dir whose name contains
// part, so the recording no longer matches its checksums.
func tamper(t *testing.T, dir, part string) {
	t.Helper()
	var hit string
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && hit == "" && d.Type().IsRegular() && strings.Contains(d.Name(), part) {
			hit = p
		}
		return err
	}))
	require.NotEmpty(t, hit, "no file matching %q", part)
	f, err := os.OpenFile(hit, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.WriteString("x")
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

func TestBSRValidatorRealRecording(t *testing.T) {
	ctx := context.Background()
	const sid = "s_1234567890"

	t.Run("valid recording", func(t *testing.T) {
		store, keys := writeRealBSR(t, sid)
		dir, err := store.Path(sid)
		require.NoError(t, err)
		v := bsrValidator{openFS: func(upload.Recording) (storage.FS, error) { return bsrfs.New(store, sid) }, unwrap: unwrapWith(keys)}
		require.NoError(t, v.Validate(ctx, upload.Recording{SessionID: sid, Dir: dir}))
	})
	t.Run("tampered file", func(t *testing.T) {
		store, keys := writeRealBSR(t, sid)
		dir, err := store.Path(sid)
		require.NoError(t, err)
		tamper(t, dir, "summary")
		v := bsrValidator{openFS: func(upload.Recording) (storage.FS, error) { return bsrfs.New(store, sid) }, unwrap: unwrapWith(keys)}
		require.ErrorIs(t, v.Validate(ctx, upload.Recording{SessionID: sid, Dir: dir}), ErrRecordingValidation)
	})
	t.Run("unwrap error", func(t *testing.T) {
		store, _ := writeRealBSR(t, sid)
		dir, err := store.Path(sid)
		require.NoError(t, err)
		unwrap := func(kms.WrappedKeys) (kms.UnwrappedKeys, error) {
			return kms.UnwrappedKeys{}, errors.New("unwrap " + canaryCred)
		}
		v := bsrValidator{openFS: func(upload.Recording) (storage.FS, error) { return bsrfs.New(store, sid) }, unwrap: unwrap}
		err = v.Validate(ctx, upload.Recording{SessionID: sid, Dir: dir})
		require.ErrorIs(t, err, ErrRecordingValidation)
		assert.NotContains(t, err.Error(), canaryCred)
	})
}

func TestFinalizerWithRealValidator(t *testing.T) {
	const sid = "s_1234567890"
	run := func(t *testing.T, tamperPart string) (upload.Result, *memBucket, *memScratch, error) {
		store, keys := writeRealBSR(t, sid)
		dir, err := store.Path(sid)
		require.NoError(t, err)
		if tamperPart != "" {
			tamper(t, dir, tamperPart)
		}
		b := &memBucket{files: map[string][]byte{}}
		sc := &memScratch{dir: dir}
		val := bsrValidator{openFS: func(upload.Recording) (storage.FS, error) { return bsrfs.New(store, sid) }, unwrap: unwrapWith(keys)}
		res, err := newFin(t, sc, b, val, &nopEvents{})
		return res, b, sc, err
	}
	t.Run("valid recording is uploaded", func(t *testing.T) {
		res, b, sc, err := run(t, "")
		require.NoError(t, err)
		assert.Equal(t, upload.StatusUploaded, res.Status)
		assert.NotEmpty(t, b.files)
		assert.True(t, sc.marked && sc.discarded)
	})
	t.Run("tampered recording is not uploaded", func(t *testing.T) {
		res, b, sc, err := run(t, "summary")
		require.Error(t, err)
		assert.Equal(t, upload.StatusInvalid, res.Status)
		assert.Empty(t, b.files, "nothing is uploaded")
		assert.False(t, sc.marked || sc.discarded, "scratch is kept")
	})
}

type typedNilSource struct{}

func (typedNilSource) Open(context.Context, string) (RecordingBucketSession, error) {
	var b *memBucket
	return b, nil
}

func TestStorageUploaderTypedNilBucketSessionFailsClosed(t *testing.T) {
	err := storageUploader{src: typedNilSource{}}.Upload(context.Background(), upload.Recording{SessionID: "s_1", Dir: t.TempDir()})
	require.ErrorIs(t, err, ErrRecordingUpload)
}
