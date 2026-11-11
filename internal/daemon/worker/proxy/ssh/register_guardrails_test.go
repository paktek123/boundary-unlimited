// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/hashicorp/boundary/internal/guardrails"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func goodGuardrailsInput() *GuardrailsInput {
	return &GuardrailsInput{
		PrincipalID: "u_1234567890",
		Rules: []guardrails.Rule{{
			ID: "r_deny", Name: "deny", ScopeID: "o_1",
			Match:     guardrails.Match{Kind: guardrails.MatchPrefix, Pattern: "rm -rf"},
			Action:    guardrails.ActionDeny,
			Selectors: guardrails.Selectors{AllTargets: true}, Message: "blocked", Enabled: true,
		}},
		Session: guardrails.SessionInfo{TargetID: "tssh_1", ScopeIDs: []string{"o_1"}},
	}
}

func grDecoder(addr string, key, hk ssh.Signer, gi *GuardrailsInput) InputDecoder {
	return func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, []HandleOption, error) {
		return SessionConfig{
			Authorization: okAuth(), ClientHostKey: key, UpstreamAddr: addr,
			Credential: injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
			HostKeys:   pinned(hk), Guardrails: gi,
		}, nil, nil
	}
}

func TestGuardrailOptions(t *testing.T) {
	ctx := context.Background()
	InstallGuardrailsEmitter(nil)
	t.Cleanup(func() { InstallGuardrailsEmitter(nil) })

	o, err := guardrailOptions(ctx, SessionConfig{})
	require.NoError(t, err)
	assert.Empty(t, o)

	_, err = guardrailOptions(ctx, SessionConfig{Guardrails: goodGuardrailsInput()})
	require.Error(t, err, "no emitter")
	var typedNil *guardrails.RecordingEmitter
	InstallGuardrailsEmitter(typedNil)
	_, err = guardrailOptions(ctx, SessionConfig{Guardrails: goodGuardrailsInput()})
	require.Error(t, err, "typed nil emitter")

	em := &guardrails.RecordingEmitter{}
	InstallGuardrailsEmitter(em)

	gi := goodGuardrailsInput()
	gi.PrincipalID = ""
	_, err = guardrailOptions(ctx, SessionConfig{Guardrails: gi})
	require.Error(t, err, "missing principal")

	gi = goodGuardrailsInput()
	gi.Rules = nil
	_, err = guardrailOptions(ctx, SessionConfig{Guardrails: gi})
	require.Error(t, err, "guardrails apply but no rules")

	gi = goodGuardrailsInput()
	gi.Rules[0].Match = guardrails.Match{Kind: guardrails.MatchRegexp, Pattern: "CANARY-(unclosed"}
	_, err = guardrailOptions(ctx, SessionConfig{Guardrails: gi})
	require.Error(t, err, "bad regexp")
	assert.NotContains(t, err.Error(), "CANARY")

	gi = goodGuardrailsInput()
	gi.BlockLimit = 99
	o, err = guardrailOptions(ctx, SessionConfig{Guardrails: gi})
	require.NoError(t, err, "limit is validated when the session starts")
	require.Len(t, o, 1)
}

func TestGuardrailOptions_EnforcesDenyAndInteractive(t *testing.T) {
	ctx := context.Background()
	em := &guardrails.RecordingEmitter{}
	InstallGuardrailsEmitter(em)
	t.Cleanup(func() { InstallGuardrailsEmitter(nil) })

	o, err := guardrailOptions(ctx, SessionConfig{Guardrails: goodGuardrailsInput()})
	require.NoError(t, err)
	var ho handleOptions
	o[0](&ho)
	require.NotNil(t, ho.guardrails)
	assert.False(t, ho.guardrails.allowInteractive, "interactive refused by default")
	assert.Equal(t, guardrails.DefaultBlocksBeforeTerminate, ho.guardrails.blockLimit)

	ft := newFakeTarget(t)
	up, err := startGuardrails(ctx, ho.guardrails, "s_1", ft)
	require.NoError(t, err)
	client, _ := startServe(t, ctx, okAuth(), up)

	const canary = "CANARY-cmd-77"
	sess, err := client.NewSession()
	require.NoError(t, err)
	ok, _ := sess.SendRequest("exec", true, execPayload("rm -rf / "+canary))
	assert.False(t, ok)
	assert.Empty(t, reqTypes(ft), "blocked command never reaches the target")
	evs := em.Events()
	require.Len(t, evs, 1)
	assert.NotContains(t, strings.Join([]string{string(evs[0].Type), evs[0].RuleId, evs[0].SessionId, evs[0].PrincipalId}, " "), canary)

	sess2, err := client.NewSession()
	require.NoError(t, err)
	ok, _ = sess2.SendRequest("shell", true, nil)
	assert.False(t, ok, "shell refused unless explicitly allowed")
	assert.Empty(t, reqTypes(ft))
}

func TestGuardrailOptions_AllowInteractiveAndBlockLimit(t *testing.T) {
	InstallGuardrailsEmitter(&guardrails.RecordingEmitter{})
	t.Cleanup(func() { InstallGuardrailsEmitter(nil) })
	gi := goodGuardrailsInput()
	gi.AllowInteractive = true
	gi.BlockLimit = 2
	o, err := guardrailOptions(context.Background(), SessionConfig{Guardrails: gi})
	require.NoError(t, err)
	var ho handleOptions
	o[0](&ho)
	assert.True(t, ho.guardrails.allowInteractive)
	assert.Equal(t, 2, ho.guardrails.blockLimit)
}

func TestHandler_GuardrailsWithoutEmitterIsRefused(t *testing.T) {
	ctx := context.Background()
	InstallGuardrailsEmitter(nil)
	pt := newPasswordTarget(t)
	withDecoder(t, grDecoder(pt.addr, newSigner(t), pt.hostKey, goodGuardrailsInput()))
	pb, err := anypb.New(&emptypb.Empty{})
	require.NoError(t, err)
	c1, c2 := net.Pipe()
	defer c1.Close()
	fn, err := registered(t)(ctx, ctx, nil, c2, nil, okAuth().ConnectionId, pb, nil)
	require.Error(t, err)
	assert.Nil(t, fn)
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, rerr := c1.Read(make([]byte, 1))
	assert.Zero(t, n)
	assert.Error(t, rerr)
	assert.Zero(t, pt.authTrys.Load(), "upstream must never be dialled")
}

func TestHandler_GuardrailsEnabledAccepted(t *testing.T) {
	ctx := context.Background()
	InstallGuardrailsEmitter(&guardrails.RecordingEmitter{})
	t.Cleanup(func() { InstallGuardrailsEmitter(nil) })
	pt := newPasswordTarget(t)
	clientKey := newSigner(t)
	withDecoder(t, grDecoder(pt.addr, clientKey, pt.hostKey, goodGuardrailsInput()))
	pb, err := anypb.New(&emptypb.Empty{})
	require.NoError(t, err)
	c1, c2 := tcpPair(t)
	fn, err := registered(t)(ctx, ctx, nil, c2, nil, okAuth().ConnectionId, pb, nil)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	sc, chans, reqs, err := ssh.NewClientConn(c1, "worker", &ssh.ClientConfig{
		User: "anyone", HostKeyCallback: ssh.FixedHostKey(clientKey.PublicKey()), Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	ssh.NewClient(sc, chans, reqs).Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return")
	}
}
