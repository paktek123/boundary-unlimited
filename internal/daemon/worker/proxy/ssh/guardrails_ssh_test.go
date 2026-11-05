// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/guardrails"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const guardCanary = "CANARY-cmd-9f3a"

func guardRules(t *testing.T) *guardrails.Compiled {
	t.Helper()
	rules := []guardrails.Rule{
		{ID: "r_deny", Name: "deny", ScopeID: "o_1", Match: guardrails.Match{Kind: guardrails.MatchPrefix, Pattern: "rm -rf"},
			Action: guardrails.ActionDeny, Selectors: guardrails.Selectors{AllTargets: true}, Message: "blocked", Enabled: true},
		{ID: "r_rev", Name: "review", ScopeID: "o_1", Match: guardrails.Match{Kind: guardrails.MatchPrefix, Pattern: "reboot"},
			Action: guardrails.ActionRequireReview, Selectors: guardrails.Selectors{AllTargets: true}, Message: "review", Enabled: true},
	}
	c, err := guardrails.Compile(rules, guardrails.SessionInfo{TargetID: "tssh_1", ScopeIDs: []string{"o_1"}}, guardrails.Limits{ReviewsSupported: true})
	require.NoError(t, err)
	return c
}

func execPayload(cmd string) []byte {
	return ssh.Marshal(struct{ Cmd string }{cmd})
}

// guardSession starts Serve through the guard and returns a client plus the target.
func guardSession(t *testing.T, ft *fakeTarget, em guardrails.Emitter, opts ...GuardrailOption) (*ssh.Client, *guardrailConfig) {
	t.Helper()
	cfg := &guardrailConfig{compiled: guardRules(t), emitter: em, principalId: "u_1", blockLimit: guardrails.DefaultBlocksBeforeTerminate}
	for _, o := range opts {
		o(cfg)
	}
	up, err := startGuardrails(context.Background(), cfg, "s_1", ft)
	require.NoError(t, err)
	client, _ := startServe(t, context.Background(), okAuth(), up)
	return client, cfg
}

func reqTypes(ft *fakeTarget) []string { return ft.seen(&ft.reqTypes) }

func TestGuardrails_AllowForwards(t *testing.T) {
	ft := newFakeTarget(t)
	em := &guardrails.RecordingEmitter{}
	client, _ := guardSession(t, ft, em)
	sess, err := client.NewSession()
	require.NoError(t, err)
	ok, err := sess.SendRequest("exec", true, execPayload("ls -la"))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, []string{"exec"}, reqTypes(ft))
	assert.Empty(t, em.Events())
}

func TestGuardrails_BlockAndReviewForwardNothing(t *testing.T) {
	tests := []struct {
		name, cmd string
		wantEv    guardrails.EventType
	}{
		{"blocked", "rm -rf / " + guardCanary, guardrails.EventBlocked},
		{"review", "reboot " + guardCanary, guardrails.EventReviewRequested},
		{"malformed utf8", "ls \xff" + guardCanary, guardrails.EventBlocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := newFakeTarget(t)
			em := &guardrails.RecordingEmitter{}
			client, _ := guardSession(t, ft, em)
			sess, err := client.NewSession()
			require.NoError(t, err)
			ok, _ := sess.SendRequest("exec", true, execPayload(tt.cmd))
			assert.False(t, ok)
			assert.Empty(t, reqTypes(ft), "nothing may reach the target")
			evs := em.Events()
			require.Len(t, evs, 1)
			assert.Equal(t, tt.wantEv, evs[0].Type)
			assert.NotContains(t, strings.Join([]string{string(evs[0].Type), evs[0].RuleId, evs[0].SessionId, evs[0].PrincipalId}, " "), guardCanary)
		})
	}
}

func TestGuardrails_MalformedExecPayloadBlocks(t *testing.T) {
	for _, p := range [][]byte{nil, {0, 0}, {0, 0, 0, 9, 'a'}, append(execPayload("ls"), 'x')} {
		ft := newFakeTarget(t)
		em := &guardrails.RecordingEmitter{}
		client, _ := guardSession(t, ft, em)
		sess, err := client.NewSession()
		require.NoError(t, err)
		ok, _ := sess.SendRequest("exec", true, p)
		assert.False(t, ok)
		assert.Empty(t, reqTypes(ft))
		assert.Len(t, em.Events(), 1)
	}
}

func TestGuardrails_InteractiveRefusedUnlessAllowed(t *testing.T) {
	for _, name := range []string{"shell", "subsystem"} {
		ft := newFakeTarget(t)
		em := &guardrails.RecordingEmitter{}
		client, _ := guardSession(t, ft, em)
		sess, err := client.NewSession()
		require.NoError(t, err)
		ok, _ := sess.SendRequest(name, true, nil)
		assert.False(t, ok, name)
		assert.Empty(t, reqTypes(ft), name)
	}

	ft := newFakeTarget(t)
	em := &guardrails.RecordingEmitter{}
	client, _ := guardSession(t, ft, em, WithGuardrailAllowInteractive())
	evs := em.Events()
	require.Len(t, evs, 1)
	assert.Equal(t, guardrails.EventInteractiveBestEffort, evs[0].Type)
	sess, err := client.NewSession()
	require.NoError(t, err)
	_, _ = sess.SendRequest("shell", true, nil)
	assert.Contains(t, reqTypes(ft), "shell")
}

func TestGuardrails_InteractiveEmitFailureRefuses(t *testing.T) {
	cfg := &guardrailConfig{compiled: guardRules(t), emitter: &guardrails.RecordingEmitter{Err: errors.New("down")},
		principalId: "u_1", blockLimit: 5, allowInteractive: true}
	_, err := startGuardrails(context.Background(), cfg, "s_1", newFakeTarget(t))
	require.Error(t, err)
}

func TestGuardrails_NthBlockTerminatesSession(t *testing.T) {
	ft := newFakeTarget(t)
	em := &guardrails.RecordingEmitter{}
	client, _ := guardSession(t, ft, em, WithGuardrailBlockLimit(2))
	for i := 0; i < 2; i++ {
		sess, err := client.NewSession()
		require.NoError(t, err, "session %d", i)
		ok, _ := sess.SendRequest("exec", true, execPayload("rm -rf /"))
		assert.False(t, ok)
	}
	var types []guardrails.EventType
	for _, e := range em.Events() {
		types = append(types, e.Type)
	}
	assert.Equal(t, []guardrails.EventType{guardrails.EventBlocked, guardrails.EventBlocked, guardrails.EventSessionTerminated}, types)
	assert.Empty(t, reqTypes(ft))
	select {
	case <-ft.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream connection not closed on termination")
	}
}

type panicEmitter struct{}

func (panicEmitter) Emit(context.Context, guardrails.Event) error { panic("boom " + guardCanary) }

func TestGuardrails_EmitterFailureOrPanicStillBlocks(t *testing.T) {
	for _, em := range []guardrails.Emitter{&guardrails.RecordingEmitter{Err: errors.New("down")}, panicEmitter{}} {
		ft := newFakeTarget(t)
		client, _ := guardSession(t, ft, em)
		sess, err := client.NewSession()
		require.NoError(t, err)
		ok, _ := sess.SendRequest("exec", true, execPayload("rm -rf /"))
		assert.False(t, ok)
		assert.Empty(t, reqTypes(ft))
	}
}

func TestGuardrails_InvalidConfigRefused(t *testing.T) {
	good := func() *guardrailConfig {
		return &guardrailConfig{compiled: guardRules(t), emitter: &guardrails.RecordingEmitter{}, principalId: "u_1", blockLimit: 5}
	}
	tests := map[string]func(*guardrailConfig){
		"nil compiled":  func(c *guardrailConfig) { c.compiled = nil },
		"nil emitter":   func(c *guardrailConfig) { c.emitter = nil },
		"no principal":  func(c *guardrailConfig) { c.principalId = "" },
		"limit zero":    func(c *guardrailConfig) { c.blockLimit = 0 },
		"limit too big": func(c *guardrailConfig) { c.blockLimit = 21 },
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			c := good()
			mut(c)
			_, err := startGuardrails(context.Background(), c, "s_1", newFakeTarget(t))
			require.Error(t, err)
		})
	}
	_, err := startGuardrails(context.Background(), good(), "s_1", newFakeTarget(t))
	require.NoError(t, err)
}

func TestHandleSession_Guardrails_InvalidRefusesBeforeDial(t *testing.T) {
	addr, dials := countingListener(t)
	pt := newPasswordTarget(t)
	rep := &fakeReporter{}
	cfg := recCfg(t, pt.addr, pt.hostKey, rep)
	cfg.UpstreamAddr = addr
	c1, c2 := tcpPair(t)
	defer c1.Close()
	err := HandleSession(context.Background(), c2, cfg, WithGuardrails(nil, &guardrails.RecordingEmitter{}))
	require.Error(t, err)
	assert.Zero(t, dials.Load())
	assert.Equal(t, [][2]string{{reportTargetId, ReasonGuardrailsUnavailable}}, rep.rejected)
}

func TestHandleSession_Guardrails_BlocksAndWithoutOptionUnchanged(t *testing.T) {
	pt := newPasswordTarget(t)
	em := &guardrails.RecordingEmitter{}
	cfg := recCfg(t, pt.addr, pt.hostKey, nil)
	c1, c2 := tcpPair(t)
	done := make(chan error, 1)
	go func() {
		done <- HandleSession(context.Background(), c2, cfg,
			WithGuardrails(guardRules(t), em, WithGuardrailPrincipalId("u_1")))
	}()
	client := dialClient(t, c1, cfg)
	sess, err := client.NewSession()
	require.NoError(t, err)
	ok, _ := sess.SendRequest("exec", true, execPayload("rm -rf /"))
	assert.False(t, ok)
	evs := em.Events()
	require.NotEmpty(t, evs)
	assert.Equal(t, guardrails.EventBlocked, evs[0].Type)
	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleSession did not return")
	}
}
