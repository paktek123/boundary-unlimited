// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/hashicorp/boundary/internal/masking"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

const maskCanary = "CANARY-pattern-9f3a(unclosed"

func maskDecoder(addr string, key, hk ssh.Signer, mi *MaskingInput) InputDecoder {
	return func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, []HandleOption, error) {
		return SessionConfig{
			Authorization: okAuth(),
			ClientHostKey: key,
			UpstreamAddr:  addr,
			Credential:    injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
			HostKeys:      pinned(hk),
			Masking:       mi,
		}, nil, nil
	}
}

func goodMaskingInput() *MaskingInput {
	return &MaskingInput{
		PrincipalID: "u_1234567890",
		Rules: []masking.PolicyRule{{Origin: masking.OriginChild, Rule: masking.Rule{
			ID: "mr_1", Detector: masking.KindEmail, Enabled: true,
			AppliesTo: masking.Selectors{AllTargets: true},
		}}},
		Session: masking.SessionInfo{TargetID: "ttcp_1"},
	}
}

func TestMaskingOptions(t *testing.T) {
	ctx := context.Background()
	InstallMaskingEmitter(nil)
	t.Cleanup(func() { InstallMaskingEmitter(nil) })

	t.Run("no masking input yields no options", func(t *testing.T) {
		o, err := maskingOptions(ctx, SessionConfig{})
		require.NoError(t, err)
		assert.Empty(t, o)
	})
	t.Run("no emitter is refused", func(t *testing.T) {
		o, err := maskingOptions(ctx, SessionConfig{Masking: goodMaskingInput()})
		require.Error(t, err)
		assert.Empty(t, o)
	})
	t.Run("typed nil emitter is refused", func(t *testing.T) {
		var re *masking.RecordingEmitter
		InstallMaskingEmitter(re)
		_, err := maskingOptions(ctx, SessionConfig{Masking: goodMaskingInput()})
		require.Error(t, err)
		InstallMaskingEmitter(nil)
	})

	InstallMaskingEmitter(&masking.RecordingEmitter{})
	t.Run("uncompilable rule is refused without leaking the pattern", func(t *testing.T) {
		mi := goodMaskingInput()
		mi.Rules = append(mi.Rules, masking.PolicyRule{Origin: masking.OriginChild, Rule: masking.Rule{
			ID: "mr_2", Detector: masking.KindRegex, Regex: maskCanary, Enabled: true,
			AppliesTo: masking.Selectors{AllTargets: true},
		}})
		_, err := maskingOptions(ctx, SessionConfig{Masking: mi})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), maskCanary)
	})
	t.Run("empty policy without AllowNoop is refused", func(t *testing.T) {
		mi := goodMaskingInput()
		mi.Rules = nil
		_, err := maskingOptions(ctx, SessionConfig{Masking: mi})
		require.Error(t, err)
	})
	t.Run("recorded session always gets built-ins even with no rules", func(t *testing.T) {
		mi := goodMaskingInput()
		mi.Rules = nil
		o, err := maskingOptions(ctx, SessionConfig{Masking: mi, RecordingEnabled: true})
		require.NoError(t, err)
		assert.Len(t, o, 3)
	})
	t.Run("valid input sets policy, required and audit", func(t *testing.T) {
		o, err := maskingOptions(ctx, SessionConfig{Masking: goodMaskingInput()})
		require.NoError(t, err)
		require.Len(t, o, 3)
		var ho handleOptions
		for _, f := range o {
			f(&ho)
		}
		assert.False(t, isNilValue(ho.masking))
		assert.True(t, ho.maskingRequired)
		require.NotNil(t, ho.maskingAudit)
		assert.Equal(t, DefaultMaskingAuditWindow, ho.maskingAudit.window)
		assert.Equal(t, "u_1234567890", ho.maskingAudit.principalID)
		// The compiled policy really redacts, including across chunks.
		var buf bytes.Buffer
		r, err := ho.masking.NewRedactor(&buf)
		require.NoError(t, err)
		_, _ = r.Write([]byte("mail bob@exa"))
		_, _ = r.Write([]byte("mple.com now"))
		require.NoError(t, r.Close())
		assert.NotContains(t, buf.String(), "bob@example.com")
		assert.Contains(t, buf.String(), "REDACTED")
	})
}

func TestHandler_MaskingRequiredWithoutEmitterIsRefused(t *testing.T) {
	ctx := context.Background()
	InstallMaskingEmitter(nil)
	pt := newPasswordTarget(t)
	withDecoder(t, maskDecoder(pt.addr, newSigner(t), pt.hostKey, goodMaskingInput()))
	pb, err := anypb.New(&emptypb.Empty{})
	require.NoError(t, err)
	c1, c2 := net.Pipe()
	defer c1.Close()
	fn, err := registered(t)(ctx, ctx, nil, c2, nil, okAuth().ConnectionId, pb, nil)
	require.Error(t, err)
	assert.Nil(t, fn)
	assert.False(t, strings.Contains(err.Error(), "u_1234567890"))
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, rerr := c1.Read(make([]byte, 1))
	assert.Zero(t, n)
	assert.Error(t, rerr)
	assert.Zero(t, pt.authTrys.Load(), "upstream must never be dialled")
}

func TestHandler_MaskingEnabledAccepted(t *testing.T) {
	ctx := context.Background()
	InstallMaskingEmitter(&masking.RecordingEmitter{})
	t.Cleanup(func() { InstallMaskingEmitter(nil) })
	pt := newPasswordTarget(t)
	clientKey := newSigner(t)
	withDecoder(t, maskDecoder(pt.addr, clientKey, pt.hostKey, goodMaskingInput()))
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
