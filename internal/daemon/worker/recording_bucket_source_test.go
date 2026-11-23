// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

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
