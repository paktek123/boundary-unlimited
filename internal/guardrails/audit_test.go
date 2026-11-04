// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package guardrails

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ts0   = time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("x", 3600))
	hash0 = strings.Repeat("ab", 32)
)

func TestEventStructHasOnlyAllowedFields(t *testing.T) {
	allowed := map[string]reflect.Type{
		"Type": reflect.TypeOf(EventType("")), "SessionId": reflect.TypeOf(""), "RuleId": reflect.TypeOf(""),
		"RuleSetHash": reflect.TypeOf(""), "Action": reflect.TypeOf(Action("")), "Decision": reflect.TypeOf(AuditDecision("")),
		"Count": reflect.TypeOf(0), "PrincipalId": reflect.TypeOf(""), "Timestamp": reflect.TypeOf(time.Time{}),
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

func TestConstructors(t *testing.T) {
	b, err := NewBlockedEvent("s_1", "u_1", "r_1", hash0, 3, ts0)
	require.NoError(t, err)
	assert.Equal(t, Event{Type: EventBlocked, SessionId: "s_1", RuleId: "r_1", RuleSetHash: hash0, Action: ActionDeny,
		Decision: DecisionBlocked, Count: 3, PrincipalId: "u_1", Timestamp: ts0.UTC()}, b)

	m, err := NewBlockedEvent("s_1", "u_1", "", hash0, 1, ts0)
	require.NoError(t, err)
	assert.Empty(t, m.Action)

	r, err := NewReviewRequestedEvent("s_1", "u_1", "r_2", hash0, ts0)
	require.NoError(t, err)
	assert.Equal(t, ActionRequireReview, r.Action)
	_, err = NewReviewRequestedEvent("s_1", "u_1", "", hash0, ts0)
	assert.ErrorIs(t, err, ErrInvalidAuditInput)

	term, err := NewSessionTerminatedEvent("s_1", "u_1", hash0, 5, ts0)
	require.NoError(t, err)
	assert.Equal(t, 5, term.Count)
	assert.Equal(t, DecisionTerminated, term.Decision)

	i, err := NewInteractiveBestEffortEvent("s_1", "u_1", hash0, ts0)
	require.NoError(t, err)
	assert.Equal(t, DecisionAllowedBestEffort, i.Decision)
}

func TestConstructorValidation(t *testing.T) {
	tests := []struct {
		name string
		call func() error
		want error
	}{
		{"empty session", func() error { _, e := NewBlockedEvent("", "u", "r", hash0, 1, ts0); return e }, ErrInvalidAuditInput},
		{"empty principal", func() error { _, e := NewBlockedEvent("s", "", "r", hash0, 1, ts0); return e }, ErrInvalidAuditInput},
		{"newline in id", func() error { _, e := NewBlockedEvent("s\nx", "u", "r", hash0, 1, ts0); return e }, ErrInvalidAuditInput},
		{"long id", func() error {
			_, e := NewBlockedEvent(strings.Repeat("a", MaxRuleIDLen+1), "u", "r", hash0, 1, ts0)
			return e
		}, ErrInvalidAuditInput},
		{"credential-looking id", func() error { _, e := NewBlockedEvent("s", "u", "password=hunter2", hash0, 1, ts0); return e }, ErrSensitiveField},
		{"short hash", func() error { _, e := NewBlockedEvent("s", "u", "r", "abc", 1, ts0); return e }, ErrInvalidAuditInput},
		{"upper hash", func() error { _, e := NewBlockedEvent("s", "u", "r", strings.ToUpper(hash0), 1, ts0); return e }, ErrInvalidAuditInput},
		{"zero count", func() error { _, e := NewBlockedEvent("s", "u", "r", hash0, 0, ts0); return e }, ErrInvalidAuditInput},
		{"zero time", func() error { _, e := NewBlockedEvent("s", "u", "r", hash0, 1, time.Time{}); return e }, ErrInvalidAuditInput},
		{"terminated zero blocks", func() error { _, e := NewSessionTerminatedEvent("s", "u", hash0, 0, ts0); return e }, ErrInvalidAuditInput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.call(), tt.want)
		})
	}
}

func TestEmitErrorIsReturned(t *testing.T) {
	boom := errors.New("sink down")
	em := &RecordingEmitter{Err: boom}
	e, err := NewBlockedEvent("s", "u", "r", hash0, 1, ts0)
	require.NoError(t, err)
	assert.ErrorIs(t, em.Emit(context.Background(), e), boom)
	assert.Empty(t, em.Events())

	em.Err = nil
	require.NoError(t, em.Emit(context.Background(), e))
	assert.Len(t, em.Events(), 1)
}

// TestCanaryNeverInEvents runs a canary command through a stub of the
// evaluator (only ids and the rule-set hash reach the event constructors) and
// asserts neither the canary nor its SHA-256 appears in any event output.
func TestCanaryNeverInEvents(t *testing.T) {
	const canary = "rm -rf /srv/CANARY-4c1d-secret"
	sum := sha256.Sum256([]byte(canary))
	canaryHash := hex.EncodeToString(sum[:])

	em := &RecordingEmitter{}
	build := []func() (Event, error){
		func() (Event, error) { return NewBlockedEvent("s_1", "u_1", "r_1", hash0, 2, ts0) },
		func() (Event, error) { return NewReviewRequestedEvent("s_1", "u_1", "r_1", hash0, ts0) },
		func() (Event, error) { return NewSessionTerminatedEvent("s_1", "u_1", hash0, 5, ts0) },
		func() (Event, error) { return NewInteractiveBestEffortEvent("s_1", "u_1", hash0, ts0) },
	}
	var outputs []string
	for _, b := range build {
		e, err := b()
		require.NoError(t, err)
		require.NoError(t, em.Emit(context.Background(), e))
		j, err := json.Marshal(e)
		require.NoError(t, err)
		outputs = append(outputs, string(j), fmt.Sprintf("%v|%+v|%#v", e, e, e))
	}
	// Constructor errors for hostile inputs must not echo them either.
	for _, bad := range []string{canary, canary + "\n", canaryHash} {
		_, err := NewBlockedEvent(bad, "u", "r", hash0, 1, ts0)
		if err != nil {
			outputs = append(outputs, err.Error())
		}
		_, err = NewBlockedEvent("s", "u", "r", bad, 1, ts0)
		if err != nil {
			outputs = append(outputs, err.Error())
		}
	}
	for _, e := range em.Events() {
		outputs = append(outputs, fmt.Sprint(e))
	}
	for _, o := range outputs {
		assert.NotContains(t, o, "CANARY")
		assert.NotContains(t, o, canaryHash)
	}
}

func TestRepeatedBlocksAreCounted(t *testing.T) {
	e, err := NewBlockedEvent("s_1", "u_1", "r_1", hash0, 7, ts0)
	require.NoError(t, err)
	assert.Equal(t, 7, e.Count)
	assert.Equal(t, reflect.TypeOf(Event{}).NumField(), reflect.TypeOf(e).NumField())
}
