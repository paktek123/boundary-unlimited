// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/masking"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAudit(t *testing.T, em masking.Emitter) *maskAudit {
	t.Helper()
	a, err := newMaskAudit(context.Background(), "s_1234567890", "u_1234567890", time.Hour, em)
	require.NoError(t, err)
	return a
}

func TestMaskingAudit_CountsOnlyEvents(t *testing.T) {
	tests := []struct {
		name   string
		writes []string
	}{
		{"single write", []string{"key=" + canaryKey + "\n"}},
		{"split across writes", []string{"key=AKIAIOSFODNN", "7EXAMPLE\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em := &masking.RecordingEmitter{}
			up := newMaskingUpstream(newFakeTarget(t), goodPolicy()).withAudit(newTestAudit(t, em))
			got, err := runEcho(t, up, tt.writes...)
			require.NoError(t, err)
			assert.NotContains(t, got, canaryKey)

			evs := em.Events()
			require.NotEmpty(t, evs)
			total := 0
			for _, e := range evs {
				total += e.Count
				assert.Equal(t, masking.EventRedactions, e.Type)
				assert.Equal(t, "s_1234567890", e.SessionId)
				assert.Equal(t, "u_1234567890", e.PrincipalId)
				assert.Equal(t, "h1", e.RuleId)
				assert.NotEmpty(t, e.Detector)
				assert.NotContains(t, fmt.Sprintf("%+v", e), canaryKey, "event must not carry the matched value")
			}
			assert.Equal(t, 1, total, "each replacement is counted exactly once")
		})
	}
}

func TestMaskingAudit_NoMatchNoEvents(t *testing.T) {
	em := &masking.RecordingEmitter{}
	up := newMaskingUpstream(newFakeTarget(t), goodPolicy()).withAudit(newTestAudit(t, em))
	got, err := runEcho(t, up, "hello\n")
	require.NoError(t, err)
	assert.Equal(t, "hello\n", got)
	assert.Empty(t, em.Events())
}

func TestMaskingAudit_EmitterFailureTerminatesChannel(t *testing.T) {
	ft := newFakeTarget(t)
	em := &masking.RecordingEmitter{Err: errors.New("sink down " + canaryKey)}
	up := newMaskingUpstream(ft, goodPolicy()).withAudit(newTestAudit(t, em))
	got, _ := runEcho(t, up, "key="+canaryKey+"\n")
	assert.Empty(t, got, "no byte may be delivered when the audit emitter fails")
	select {
	case <-ft.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream connection must be closed when the audit emitter fails")
	}
}

func TestMaskingAudit_ReaderFailsClosedOnMidStreamEmitterError(t *testing.T) {
	em := &masking.RecordingEmitter{}
	a, err := newMaskAudit(context.Background(), "s_1234567890", "u_1234567890", time.Nanosecond, em)
	require.NoError(t, err)
	terminated := false
	src := strings.NewReader("a=" + canaryKey + " b=" + canaryKey + " " + strings.Repeat("x", 200))
	m, err := newMaskReaderAudit(goodPolicy(), src, func() { terminated = true }, a)
	require.NoError(t, err)
	em.Err = errors.New("sink down")
	b, err := io.ReadAll(m)
	assert.Error(t, err)
	assert.Empty(t, b)
	assert.True(t, terminated)
	assert.NotContains(t, err.Error(), "sink down")
}

func TestMaskingAudit_InvalidConfigRejected(t *testing.T) {
	em := &masking.RecordingEmitter{}
	ctx := context.Background()
	for name, f := range map[string]func() (*maskAudit, error){
		"nil emitter":       func() (*maskAudit, error) { return newMaskAudit(ctx, "s_1", "u_1", time.Second, nil) },
		"zero window":       func() (*maskAudit, error) { return newMaskAudit(ctx, "s_1", "u_1", 0, em) },
		"empty principal":   func() (*maskAudit, error) { return newMaskAudit(ctx, "s_1", "", time.Second, em) },
		"credential-ish id": func() (*maskAudit, error) { return newMaskAudit(ctx, "password=hunter2", "u_1", time.Second, em) },
	} {
		t.Run(name, func(t *testing.T) {
			a, err := f()
			require.Error(t, err)
			assert.Nil(t, a)
			assert.NotContains(t, err.Error(), "hunter2")
		})
	}
}

func TestMaskingAudit_NilAuditIsNoop(t *testing.T) {
	var a *maskAudit
	assert.Nil(t, a.callback("h"))
	assert.False(t, a.failed())
	assert.NoError(t, a.flush())
}

func TestMaskingAudit_RealPolicyAcceptsOptions(t *testing.T) {
	var _ MaskingPolicy = (*masking.Policy)(nil)
}
