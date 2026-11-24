// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
	"github.com/stretchr/testify/require"
)

type fakeBucketSession struct{ closed bool }

func (f *fakeBucketSession) Put(context.Context, string, io.Reader) error { return nil }
func (f *fakeBucketSession) Close() error                                 { f.closed = true; return nil }

const canarySecret = "canary-secret-value-123"

func TestSessionBucketSourceFailsClosed(t *testing.T) {
	okLookup := func(context.Context, string) (SessionBucketRef, error) {
		return SessionBucketRef{BucketId: "sb_1", Secret: []byte(canarySecret)}, nil
	}
	okOpen := func(context.Context, SessionBucketRef) (RecordingBucketSession, error) {
		return &fakeBucketSession{}, nil
	}
	tests := []struct {
		name    string
		src     RecordingBucketSource
		session string
		wantErr bool
	}{
		{"success", NewSessionBucketSource(okLookup, okOpen), "s_1", false},
		{"nil deps", NewSessionBucketSource(nil, nil), "s_1", true},
		{"empty session", NewSessionBucketSource(okLookup, okOpen), "", true},
		{"no bucket", NewSessionBucketSource(func(context.Context, string) (SessionBucketRef, error) {
			return SessionBucketRef{}, ErrNoRecordingBucket
		}, okOpen), "s_1", true},
		{"empty bucket id", NewSessionBucketSource(func(context.Context, string) (SessionBucketRef, error) {
			return SessionBucketRef{}, nil
		}, okOpen), "s_1", true},
		{"lookup error leaks nothing", NewSessionBucketSource(func(context.Context, string) (SessionBucketRef, error) {
			return SessionBucketRef{}, errors.New(canarySecret)
		}, okOpen), "s_1", true},
		{"open error leaks nothing", NewSessionBucketSource(okLookup, func(context.Context, SessionBucketRef) (RecordingBucketSession, error) {
			return nil, errors.New(canarySecret)
		}), "s_1", true},
		{"nil session", NewSessionBucketSource(okLookup, func(context.Context, SessionBucketRef) (RecordingBucketSession, error) {
			var f *fakeBucketSession
			return f, nil
		}), "s_1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs, err := tt.src.Open(context.Background(), tt.session)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrRecordingBucketUnavailable)
				require.Nil(t, bs)
				require.NotContains(t, err.Error(), canarySecret)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bs)
		})
	}
}

func TestSessionBucketRefRedacted(t *testing.T) {
	r := SessionBucketRef{BucketId: "sb_1", Secret: []byte(canarySecret)}
	for _, s := range []string{fmt.Sprintf("%v", r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r), fmt.Sprint(r)} {
		require.False(t, strings.Contains(s, canarySecret), s)
	}
}

type errCloseSession struct{ closed bool }

func (f *errCloseSession) Put(context.Context, string, io.Reader) error { return nil }
func (f *errCloseSession) Close() error                                 { f.closed = true; return nil }

func TestSessionBucketSourceClosesSessionOnOpenError(t *testing.T) {
	bs := &errCloseSession{}
	src := NewSessionBucketSource(
		func(context.Context, string) (SessionBucketRef, error) {
			return SessionBucketRef{BucketId: "sb_1"}, nil
		},
		func(context.Context, SessionBucketRef) (RecordingBucketSession, error) {
			return bs, errors.New("boom")
		},
	)
	_, err := src.Open(context.Background(), "s_1")
	require.ErrorIs(t, err, ErrRecordingBucketUnavailable)
	require.True(t, bs.closed)
}

func TestSessionBucketRefJSONRedacted(t *testing.T) {
	b, err := json.Marshal(SessionBucketRef{BucketId: "sb_1", Secret: []byte(canaryCred)})
	require.NoError(t, err)
	require.NotContains(t, string(b), canaryCred)
	b, err = json.Marshal(&SessionBucketRef{BucketId: "sb_1", Secret: []byte(canaryCred)})
	require.NoError(t, err)
	require.NotContains(t, string(b), canaryCred)
}

func TestFinalizerUploadsViaSessionBucketSource(t *testing.T) {
	sc, b, ev := &memScratch{dir: recDir(t)}, &memBucket{files: map[string][]byte{}}, &nopEvents{}
	var gotRef SessionBucketRef
	src := NewSessionBucketSource(
		func(context.Context, string) (SessionBucketRef, error) {
			return SessionBucketRef{BucketId: "sb_1", Secret: []byte(canaryCred)}, nil
		},
		func(_ context.Context, ref SessionBucketRef) (RecordingBucketSession, error) {
			gotRef = ref
			return b, nil
		},
	)
	f, err := newRecordingFinalizer(recordingFinalizerDeps{
		Scratch: sc, Buckets: src, Validator: okValidator{}, Clock: noSleep{}, Events: ev,
		Options: upload.Options{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})
	require.NoError(t, err)
	res, err := f.Finalize(context.Background(), "s_1234567890")
	require.NoError(t, err)
	require.Equal(t, upload.StatusUploaded, res.Status)
	require.Equal(t, "sb_1", gotRef.BucketId)
	require.Equal(t, map[string][]byte{"a.meta": []byte("a"), "sub/b.data": []byte("b")}, b.files)
	require.True(t, b.closed)
}

func TestFinalizerKeepsScratchWhenNoBucket(t *testing.T) {
	sc, ev := &memScratch{dir: recDir(t)}, &nopEvents{}
	src := NewSessionBucketSource(
		func(context.Context, string) (SessionBucketRef, error) {
			return SessionBucketRef{Secret: []byte(canaryCred)}, ErrNoRecordingBucket
		},
		func(context.Context, SessionBucketRef) (RecordingBucketSession, error) { return nil, nil },
	)
	f, err := newRecordingFinalizer(recordingFinalizerDeps{
		Scratch: sc, Buckets: src, Validator: okValidator{}, Clock: noSleep{}, Events: ev,
		Options: upload.Options{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})
	require.NoError(t, err)
	_, err = f.Finalize(context.Background(), "s_1234567890")
	require.Error(t, err)
	require.False(t, sc.marked)
	require.False(t, sc.discarded)
	require.NotContains(t, err.Error(), canaryCred)
	require.NotContains(t, fmt.Sprintf("%+v", ev.evs), canaryCred)
}
