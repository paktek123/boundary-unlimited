// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/hostkey"
	"github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func validInput(t *testing.T) *services.SshSessionInput {
	t.Helper()
	k, err := hostkey.Generate(context.Background())
	require.NoError(t, err)
	return &services.SshSessionInput{
		SessionId:        "s_1234567890",
		ConnectionId:     "sc_1234567890",
		TargetId:         "tssh_1234567890",
		UpstreamAddress:  "10.0.0.5:22",
		PinnedHostKeys:   []string{k.AuthorizedKey},
		RecordingEnabled: true,
		Expiration:       timestamppb.New(time.Now().Add(time.Hour)),
	}
}

func mustAny(t *testing.T, m *services.SshSessionInput) *anypb.Any {
	t.Helper()
	a, err := anypb.New(m)
	require.NoError(t, err)
	return a
}

func TestDecodeSessionInput(t *testing.T) {
	ctx := context.Background()
	t.Run("valid", func(t *testing.T) {
		in := validInput(t)
		cfg, _, err := DecodeSessionInput(ctx, nil, mustAny(t, in))
		require.NoError(t, err)
		require.Equal(t, "sc_1234567890", cfg.Authorization.ConnectionId)
		require.Equal(t, "10.0.0.5:22", cfg.UpstreamAddr)
		require.Equal(t, in.PinnedHostKeys, cfg.HostKeys.PinnedKeys)
		require.True(t, cfg.RecordingEnabled)
		require.NotNil(t, cfg.ClientHostKey)
	})

	canary := "ssh-ed25519 CANARY-KEY-MATERIAL-0123456789"
	mut := func(f func(*services.SshSessionInput)) *anypb.Any {
		in := validInput(t)
		f(in)
		return mustAny(t, in)
	}
	cases := map[string]*anypb.Any{
		"nil message":          nil,
		"wrong type":           mustAnyWrapper(t),
		"no session id":        mut(func(i *services.SshSessionInput) { i.SessionId = "" }),
		"no connection id":     mut(func(i *services.SshSessionInput) { i.ConnectionId = "" }),
		"no address":           mut(func(i *services.SshSessionInput) { i.UpstreamAddress = "" }),
		"address without port": mut(func(i *services.SshSessionInput) { i.UpstreamAddress = "host" }),
		"empty policy":         mut(func(i *services.SshSessionInput) { i.PinnedHostKeys = nil }),
		"oversize key list": mut(func(i *services.SshSessionInput) {
			i.PinnedHostKeys = make([]string, 17)
		}),
		"oversize id":   mut(func(i *services.SshSessionInput) { i.TargetId = strings.Repeat("a", 257) }),
		"invalid key":   mut(func(i *services.SshSessionInput) { i.PinnedHostKeys = []string{canary} }),
		"no expiration": mut(func(i *services.SshSessionInput) { i.Expiration = nil }),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := DecodeSessionInput(ctx, nil, a)
			require.Error(t, err)
			require.NotContains(t, err.Error(), canary)
			require.NotContains(t, err.Error(), "CANARY")
		})
	}
}

func mustAnyWrapper(t *testing.T) *anypb.Any {
	a, err := anypb.New(wrapperspb.String("x"))
	require.NoError(t, err)
	return a
}

func TestSetInputDecoderNilRefusesAll(t *testing.T) {
	old := decodeInput
	t.Cleanup(func() { decodeInput = old })
	InstallSessionInputDecoder()
	SetInputDecoder(nil)
	_, _, err := decodeInput(context.Background(), nil, mustAny(t, validInput(t)))
	require.Error(t, err)
}
