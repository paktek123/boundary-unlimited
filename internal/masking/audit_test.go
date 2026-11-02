// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package masking

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newAgg(t *testing.T, em Emitter) (*Aggregator, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	a, err := NewAggregator("s_1", "u_1", time.Minute, em, c.now)
	require.NoError(t, err)
	return a, c
}

func TestEventStructHasOnlyAllowedFields(t *testing.T) {
	allowed := map[string]reflect.Type{
		"Type": reflect.TypeOf(EventType("")), "SessionId": reflect.TypeOf(""), "RuleId": reflect.TypeOf(""),
		"Detector": reflect.TypeOf(""), "Count": reflect.TypeOf(0),
		"WindowStart": reflect.TypeOf(time.Time{}), "WindowEnd": reflect.TypeOf(time.Time{}),
		"PrincipalId": reflect.TypeOf(""),
	}
	typ := reflect.TypeOf(Event{})
	require.Equal(t, len(allowed), typ.NumField(), "an Event field was added or removed: review it against the security decision")
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		want, ok := allowed[f.Name]
		require.True(t, ok, "unexpected field %s", f.Name)
		assert.Equal(t, want, f.Type, f.Name)
	}
}

func TestAggregatorWindows(t *testing.T) {
	em := &RecordingEmitter{}
	a, c := newAgg(t, em)
	ctx := context.Background()

	require.NoError(t, a.Add(ctx, "r1", "email", 2))
	require.NoError(t, a.Add(ctx, "r1", "email", 3))
	require.NoError(t, a.Add(ctx, "r2", "jwt", 1))
	require.NoError(t, a.Add(ctx, "r3", "jwt", 0)) // zero count records nothing
	assert.Empty(t, em.Events(), "nothing is emitted inside the window")

	c.t = c.t.Add(time.Minute) // window ended: next Add flushes it
	require.NoError(t, a.Add(ctx, "r1", "email", 4))
	ev := em.Events()
	require.Len(t, ev, 2)
	assert.Equal(t, Event{Type: EventRedactions, SessionId: "s_1", RuleId: "r1", Detector: "email", Count: 5,
		WindowStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), WindowEnd: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC), PrincipalId: "u_1"}, ev[0])
	assert.Equal(t, "r2", ev[1].RuleId)
	assert.Equal(t, 1, ev[1].Count)

	// Flush emits the open window once, then nothing (zero-count windows emit nothing).
	c.t = c.t.Add(10 * time.Second)
	require.NoError(t, a.Flush(ctx))
	require.NoError(t, a.Flush(ctx))
	ev = em.Events()
	require.Len(t, ev, 3)
	assert.Equal(t, 4, ev[2].Count)

	empty := &RecordingEmitter{}
	a2, _ := newAgg(t, empty)
	require.NoError(t, a2.Flush(ctx))
	assert.Empty(t, empty.Events())
}

func TestAggregatorEmitFailureKeepsCounts(t *testing.T) {
	em := &RecordingEmitter{Err: errors.New("sink down")}
	a, _ := newAgg(t, em)
	ctx := context.Background()
	require.NoError(t, a.Add(ctx, "r1", "email", 2))
	require.Error(t, a.Flush(ctx))
	em.Err = nil
	require.NoError(t, a.Flush(ctx))
	require.Len(t, em.Events(), 1)
	assert.Equal(t, 2, em.Events()[0].Count)
}

func TestAggregatorValidation(t *testing.T) {
	em := &RecordingEmitter{}
	for _, tc := range []struct {
		name   string
		s, p   string
		window time.Duration
		em     Emitter
	}{
		{"empty session", "", "u", time.Minute, em},
		{"empty principal", "s", "", time.Minute, em},
		{"zero window", "s", "u", 0, em},
		{"nil emitter", "s", "u", time.Minute, nil},
		{"control chars", "s\n1", "u", time.Minute, em},
		{"credential-like", "s", "AKIAIOSFODNN7EXAMPLE", time.Minute, em},
		{"too long", strings.Repeat("a", 129), "u", time.Minute, em},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAggregator(tc.s, tc.p, tc.window, tc.em, nil)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "AKIAIOSFODNN7EXAMPLE")
		})
	}
	a, _ := newAgg(t, em)
	err := a.Add(context.Background(), "password=hunter2", "email", 1)
	require.ErrorIs(t, err, ErrSensitiveField)
	assert.NotContains(t, err.Error(), "hunter2")
	require.Error(t, a.Add(context.Background(), "r1", "", 1))
}

// TestCanaryNeverInEventsErrorsOrLogs runs a canary secret and a canary
// replacement through a redactor, feeds the redaction count to the
// aggregator and checks that neither canary appears in any event, error or
// log line.
func TestCanaryNeverInEventsErrorsOrLogs(t *testing.T) {
	const (
		secret      = "SECRETCANARY-4242"
		replacement = "REPLCANARY-77"
	)
	rules := []Rule{{ID: "r_canary", Detector: KindRegex, Regex: `SECRETCANARY-[0-9]+`, Replacement: replacement, AppliesTo: Selectors{AllTargets: true}, Enabled: true}}
	comp, err := Compile(rules, sess, Limits{})
	require.NoError(t, err)
	var out bytes.Buffer
	red, err := comp.NewRedactor(&out)
	require.NoError(t, err)
	_, err = red.Write([]byte("a " + secret + " b " + secret + " c"))
	require.NoError(t, err)
	require.NoError(t, red.Close())
	n := strings.Count(out.String(), replacement)
	require.Equal(t, 2, n)

	em := &RecordingEmitter{}
	a, c := newAgg(t, em)
	var logs []string
	record := func(err error) {
		if err != nil {
			logs = append(logs, err.Error())
		}
	}
	record(a.Add(context.Background(), comp.RuleIDs()[0], "regex", n))
	c.t = c.t.Add(time.Hour)
	record(a.Flush(context.Background()))
	// Failure path as well.
	em.Err = errors.New("sink down")
	record(a.Add(context.Background(), "r_canary", "regex", n))
	record(a.Flush(context.Background()))

	captured := fmt.Sprintf("%+v %q", em.Events(), logs)
	assert.NotContains(t, captured, secret)
	assert.NotContains(t, captured, replacement)
	require.Len(t, em.Events(), 1)
	assert.Equal(t, 2, em.Events()[0].Count)
}
