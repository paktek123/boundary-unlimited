// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/guardrails"
	"github.com/hashicorp/boundary/internal/masking"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captured struct {
	op   event.Op
	msg  string
	args []any
}

func capture(out *[]captured) sysEventWriter {
	return func(_ context.Context, op event.Op, msg string, args ...any) {
		*out = append(*out, captured{op, msg, args})
	}
}

func TestEmittersAreCountsOnly(t *testing.T) {
	const canary = "CANARY-SECRET-VALUE"
	var got []captured
	w := capture(&got)
	now := time.Unix(1700000000, 0)

	require.NoError(t, maskingSysEmitter{w}.Emit(context.Background(), masking.Event{
		Type: masking.EventRedactions, SessionId: "s_1", RuleId: "r1", Detector: "aws", Count: 3,
		WindowStart: now, WindowEnd: now, PrincipalId: "u_1",
	}))
	require.NoError(t, guardrailsSysEmitter{w}.Emit(context.Background(), guardrails.Event{
		Type: guardrails.EventBlocked, SessionId: "s_1", RuleId: "r2", Count: 1, PrincipalId: "u_1", Timestamp: now,
	}))
	require.Len(t, got, 2)
	for _, c := range got {
		assert.NotContains(t, c.msg, canary)
		keys := map[string]bool{}
		for i := 0; i < len(c.args); i += 2 {
			keys[c.args[i].(string)] = true
		}
		for k := range keys {
			assert.False(t, strings.Contains(k, "value") || strings.Contains(k, "match") || strings.Contains(k, "command"), k)
		}
	}
	assert.Equal(t, 7*2, len(got[0].args))

	assert.Error(t, maskingSysEmitter{}.Emit(context.Background(), masking.Event{}))
	assert.Error(t, guardrailsSysEmitter{}.Emit(context.Background(), guardrails.Event{}))
}

func TestNewSSHScratch(t *testing.T) {
	s, err := newSSHScratch("")
	require.NoError(t, err)
	assert.Nil(t, s, "no storage configured -> no scratch store")

	s, err = newSSHScratch(t.TempDir())
	require.NoError(t, err)
	assert.NotNil(t, s)
}

func TestRecoverSSHScratch(t *testing.T) {
	ctx := context.Background()
	var got []captured

	// nil store is a no-op.
	require.NoError(t, recoverSSHScratch(ctx, nil, capture(&got)))
	assert.Empty(t, got)

	root := t.TempDir()
	old, err := scratch.New(root, 1024)
	require.NoError(t, err)
	require.NoError(t, old.Reserve("s_orphan1", 100))
	_, err = old.Write("s_orphan1", []byte("data"))
	require.NoError(t, err)

	st, err := scratch.New(root, 1024)
	require.NoError(t, err)
	require.NoError(t, recoverSSHScratch(ctx, st, capture(&got)))
	require.Len(t, got, 1)
	assert.Equal(t, []any{"orphans", 1}, got[0].args)
	assert.Positive(t, st.Used(), "orphan accounted against quota, not deleted")
}
