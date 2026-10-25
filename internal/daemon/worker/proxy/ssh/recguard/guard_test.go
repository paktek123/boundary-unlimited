// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package recguard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSink struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	calls  int
	failAt int // 1-based call number that fails; 0 never fails
	err    error
	short  bool
}

func (s *fakeSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failAt != 0 && s.calls >= s.failAt {
		if s.short {
			return len(p) - 1, nil
		}
		return 0, s.err
	}
	return s.buf.Write(p)
}

type fakeTerm struct {
	mu      sync.Mutex
	calls   int
	reasons []string
	err     error
}

func (t *fakeTerm) Terminate(_ context.Context, reason string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.calls++
	t.reasons = append(t.reasons, reason)
	return t.err
}

type fakeMark struct {
	mu      sync.Mutex
	calls   int
	reasons []string
	err     error
}

func (m *fakeMark) MarkIncomplete(_ context.Context, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.reasons = append(m.reasons, reason)
	return m.err
}

func TestNewRejectsNilDependencies(t *testing.T) {
	var nilSink *fakeSink
	var nilTerm *fakeTerm
	var nilMark *fakeMark
	tests := []struct {
		name string
		s    Sink
		t    Terminator
		m    Marker
	}{
		{"nil sink", nil, &fakeTerm{}, &fakeMark{}},
		{"nil terminator", &fakeSink{}, nil, &fakeMark{}},
		{"nil marker", &fakeSink{}, &fakeTerm{}, nil},
		{"typed nil sink", nilSink, &fakeTerm{}, &fakeMark{}},
		{"typed nil terminator", &fakeSink{}, nilTerm, &fakeMark{}},
		{"typed nil marker", &fakeSink{}, &fakeTerm{}, nilMark},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := New(tt.s, tt.t, tt.m)
			require.Error(t, err)
			assert.Nil(t, g)
		})
	}
}

func TestPassThroughInOrder(t *testing.T) {
	s, term, mark := &fakeSink{}, &fakeTerm{}, &fakeMark{}
	g, err := New(s, term, mark)
	require.NoError(t, err)

	for _, p := range []string{"one", "two", "three"} {
		n, err := g.Write([]byte(p))
		require.NoError(t, err)
		assert.Equal(t, len(p), n)
	}
	assert.Equal(t, "onetwothree", s.buf.String())
	assert.False(t, g.Tripped())
	assert.NoError(t, g.Err())
	assert.Zero(t, term.calls)
	assert.Zero(t, mark.calls)
}

func TestFailuresFailClosed(t *testing.T) {
	const secret = "TOPSECRETKEYSTROKES"
	tests := []struct {
		name    string
		sink    *fakeSink
		term    *fakeTerm
		mark    *fakeMark
		wantErr string // expected substring of g.Err(); empty means nil
	}{
		{"write error", &fakeSink{failAt: 2, err: errors.New("disk exploded " + secret)}, &fakeTerm{}, &fakeMark{}, ""},
		{"quota exceeded", &fakeSink{failAt: 2, err: errors.New("quota exceeded")}, &fakeTerm{}, &fakeMark{}, ""},
		{"short write", &fakeSink{failAt: 2, short: true}, &fakeTerm{}, &fakeMark{}, ""},
		{"terminator fails but marker still runs", &fakeSink{failAt: 2, err: io.ErrClosedPipe}, &fakeTerm{err: errors.New("term boom")}, &fakeMark{}, "term boom"},
		{"marker fails but terminator still runs", &fakeSink{failAt: 2, err: io.ErrClosedPipe}, &fakeTerm{}, &fakeMark{err: errors.New("mark boom")}, "mark boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := New(tt.sink, tt.term, tt.mark)
			require.NoError(t, err)

			_, err = g.Write([]byte("first"))
			require.NoError(t, err)

			_, err = g.Write([]byte(secret))
			require.ErrorIs(t, err, ErrRecordingFailed)
			assert.NotContains(t, err.Error(), secret)
			assert.True(t, g.Tripped())

			assert.Equal(t, 1, tt.term.calls)
			assert.Equal(t, 1, tt.mark.calls)
			for _, r := range append(append([]string{}, tt.term.reasons...), tt.mark.reasons...) {
				assert.NotContains(t, r, secret)
				assert.NotContains(t, r, "disk exploded")
			}

			// Writes after failure never reach the sink and never succeed.
			callsBefore := tt.sink.calls
			for i := 0; i < 3; i++ {
				n, err := g.Write([]byte("later"))
				require.ErrorIs(t, err, ErrRecordingFailed)
				assert.Zero(t, n)
			}
			assert.Equal(t, callsBefore, tt.sink.calls)
			assert.NotContains(t, tt.sink.buf.String(), "later")
			assert.Equal(t, 1, tt.term.calls, "terminator called exactly once")
			assert.Equal(t, 1, tt.mark.calls, "marker called exactly once")

			if tt.wantErr == "" {
				assert.NoError(t, g.Err())
			} else {
				require.Error(t, g.Err())
				assert.Contains(t, g.Err().Error(), tt.wantErr)
				assert.NotContains(t, g.Err().Error(), secret)
			}
		})
	}
}

func TestConcurrentFailuresTerminateOnce(t *testing.T) {
	s := &fakeSink{failAt: 5, err: errors.New("boom")}
	term, mark := &fakeTerm{}, &fakeMark{}
	g, err := New(s, term, mark)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = g.Write([]byte("data"))
		}()
	}
	wg.Wait()

	assert.True(t, g.Tripped())
	assert.Equal(t, 1, term.calls)
	assert.Equal(t, 1, mark.calls)
	assert.Equal(t, "datadatadatadata", s.buf.String(), "only the writes before the failure succeeded")
	assert.Equal(t, 5, s.calls, "sink is not called after the first failure")
}
