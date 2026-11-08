// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package masking

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countRec struct{ got map[string]int }

func (c *countRec) cb(d string, n int) {
	if c.got == nil {
		c.got = map[string]int{}
	}
	c.got[d] += n
}

func TestOnRedactCounts(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]int
	}{
		{"single", "a " + testAWS + " b", map[string]int{"aws_access_key": 1}},
		{"multiple same", testAWS + " " + testAWS, map[string]int{"aws_access_key": 2}},
		{"none", "nothing to see", map[string]int{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &countRec{}
			out := redactAll(t, tc.in, WithOnRedact(rec.cb))
			assert.NotContains(t, out, testAWS)
			if len(tc.want) == 0 {
				assert.Empty(t, rec.got, "no callback without matches")
				return
			}
			assert.Equal(t, tc.want, rec.got)
		})
	}
}

func TestOnRedactMultipleDetectors(t *testing.T) {
	rec := &countRec{}
	redactAll(t, testAWS+" "+testCard+" "+testJWT, WithOnRedact(rec.cb))
	assert.Len(t, rec.got, 3)
	for d, n := range rec.got {
		assert.Equal(t, 1, n, d)
	}
}

func TestOnRedactSplitAtEveryOffsetCountsOnce(t *testing.T) {
	in := "x " + testAWS + " y"
	for i := 0; i <= len(in); i++ {
		rec := &countRec{}
		var buf bytes.Buffer
		r, err := New(&buf, WithOnRedact(rec.cb))
		require.NoError(t, err)
		_, err = r.Write([]byte(in[:i]))
		require.NoError(t, err)
		_, err = r.Write([]byte(in[i:]))
		require.NoError(t, err)
		require.NoError(t, r.Close())
		total := 0
		for _, n := range rec.got {
			total += n
		}
		assert.Equal(t, 1, total, "split at %d", i)
	}
}

func TestOnRedactPanicFailsClosed(t *testing.T) {
	var buf bytes.Buffer
	r, err := New(&buf, WithOnRedact(func(string, int) { panic(canary) }))
	require.NoError(t, err)
	_, err = r.Write([]byte("hello " + testAWS + " tail"))
	if err == nil {
		err = r.Close()
	}
	require.ErrorIs(t, err, ErrInternal)
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", err, err, err), canary)
	assert.Empty(t, buf.String(), "nothing may be emitted")
	_, err = r.Write([]byte("more"))
	assert.ErrorIs(t, err, ErrInternal)
}

func TestOnRedactCanaryAbsentFromCallback(t *testing.T) {
	var args []string
	det, derr := NewRegexDetector("canary", canary)
	require.NoError(t, derr)
	var buf bytes.Buffer
	r, err := New(&buf, WithDetectors(det), WithOnRedact(func(d string, n int) {
		args = append(args, fmt.Sprintf("%v %+v %#v|%d", d, d, d, n))
	}))
	require.NoError(t, err)
	_, err = r.Write([]byte("a " + canary + " b"))
	require.NoError(t, err)
	require.NoError(t, r.Close())
	require.Len(t, args, 1)
	assert.NotContains(t, args[0], canary)
	assert.NotContains(t, buf.String(), canary)
}

func TestAggregatorRedactorCallback(t *testing.T) {
	em := &RecordingEmitter{}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a, err := NewAggregator("s_1", "u_1", time.Minute, em, func() time.Time { return now })
	require.NoError(t, err)
	var buf bytes.Buffer
	r, err := New(&buf, WithOnRedact(a.RedactorCallback("rule_1")))
	require.NoError(t, err)
	_, err = r.Write([]byte(testAWS + " " + testAWS + " " + testCard))
	require.NoError(t, err)
	require.NoError(t, r.Close())
	require.NoError(t, a.Flush(context.Background()))
	ev := em.Events()
	require.Len(t, ev, 2)
	got := map[string]int{}
	for _, e := range ev {
		assert.Equal(t, "rule_1", e.RuleId)
		got[e.Detector] = e.Count
	}
	assert.Equal(t, map[string]int{"aws_access_key": 2, "credit_card": 1}, got)
}
