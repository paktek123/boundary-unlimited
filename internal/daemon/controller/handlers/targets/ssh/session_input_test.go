// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	workerssh "github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh"
	"github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func testPubKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	spk, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(spk)))
}

func validArgs(t *testing.T) SessionInputArgs {
	return SessionInputArgs{
		SessionId: "s_1234567890", ConnectionId: "sc_1234567890", TargetId: "tssh_1234567890",
		UpstreamAddress: "10.0.0.1:22", PinnedHostKeys: []string{testPubKey(t)},
		RecordingEnabled: true, Expiration: time.Now().Add(time.Hour),
	}
}

func TestBuildSessionInput(t *testing.T) {
	ctx := context.Background()
	t.Run("round trips through the worker decoder", func(t *testing.T) {
		a := validArgs(t)
		msg, err := BuildSessionInput(ctx, a)
		require.NoError(t, err)
		in := &services.SshSessionInput{}
		require.NoError(t, msg.UnmarshalTo(in))
		assert.Equal(t, a.PinnedHostKeys, in.GetPinnedHostKeys())
		assert.True(t, in.GetRecordingEnabled())
		cfg, _, err := workerssh.DecodeSessionInput(ctx, nil, msg)
		require.NoError(t, err)
		assert.Equal(t, a.SessionId, cfg.Authorization.SessionId)
		assert.Equal(t, a.UpstreamAddress, cfg.UpstreamAddr)
		assert.True(t, cfg.RecordingEnabled)
	})
	t.Run("host CA only is accepted", func(t *testing.T) {
		a := validArgs(t)
		a.HostCAs, a.PinnedHostKeys = []string{testPubKey(t)}, nil
		_, err := BuildSessionInput(ctx, a)
		require.NoError(t, err)
	})
	const canary = "ssh-ed25519 CANARYKEYMATERIAL"
	for name, mod := range map[string]func(*SessionInputArgs){
		"no session id":       func(a *SessionInputArgs) { a.SessionId = "" },
		"no connection id":    func(a *SessionInputArgs) { a.ConnectionId = "" },
		"no target id":        func(a *SessionInputArgs) { a.TargetId = "" },
		"no address":          func(a *SessionInputArgs) { a.UpstreamAddress = "" },
		"address bad port":    func(a *SessionInputArgs) { a.UpstreamAddress = "host:abc" },
		"address port 0":      func(a *SessionInputArgs) { a.UpstreamAddress = "host:0" },
		"address no host":     func(a *SessionInputArgs) { a.UpstreamAddress = ":22" },
		"address no port":     func(a *SessionInputArgs) { a.UpstreamAddress = "host" },
		"oversized id":        func(a *SessionInputArgs) { a.SessionId = strings.Repeat("a", 257) },
		"no policy (no TOFU)": func(a *SessionInputArgs) { a.PinnedHostKeys, a.HostCAs = nil, nil },
		"malformed key":       func(a *SessionInputArgs) { a.PinnedHostKeys = []string{canary} },
		"malformed ca":        func(a *SessionInputArgs) { a.HostCAs = []string{canary} },
		"wildcard key":        func(a *SessionInputArgs) { a.PinnedHostKeys = []string{"* " + canary} },
		"too many entries": func(a *SessionInputArgs) {
			a.PinnedHostKeys = nil
			for i := 0; i < 17; i++ {
				a.PinnedHostKeys = append(a.PinnedHostKeys, testPubKey(t))
			}
		},
		"no expiration": func(a *SessionInputArgs) { a.Expiration = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			a := validArgs(t)
			mod(&a)
			msg, err := BuildSessionInput(ctx, a)
			require.Error(t, err)
			assert.Nil(t, msg)
			assert.NotContains(t, err.Error(), "CANARYKEYMATERIAL")
		})
	}
}

// TestSessionInputHasNoCredentialFields guards the "no credentials in the
// worker handler argument" criterion of #347: neither the builder arguments
// nor the SshSessionInput message may have a credential-like field.
func TestSessionInputHasNoCredentialFields(t *testing.T) {
	bad := []string{"password", "passphrase", "secret", "token", "private", "credential"}
	var names []string
	rt := reflect.TypeOf(SessionInputArgs{})
	for i := 0; i < rt.NumField(); i++ {
		names = append(names, rt.Field(i).Name)
	}
	md := (&services.SshSessionInput{}).ProtoReflect().Descriptor()
	for i := 0; i < md.Fields().Len(); i++ {
		names = append(names, string(md.Fields().Get(i).Name()))
	}
	require.NotEmpty(t, names)
	for _, n := range names {
		for _, b := range bad {
			assert.NotContains(t, strings.ToLower(n), b, "field %s", n)
		}
	}
}

func TestBuildSessionInputRefusesOversizedField(t *testing.T) {
	big := strings.Repeat("t", maxSessionInputFieldLength+1)
	for name, mod := range map[string]func(*SessionInputArgs){
		"session id":       func(a *SessionInputArgs) { a.SessionId = big },
		"connection id":    func(a *SessionInputArgs) { a.ConnectionId = big },
		"target id":        func(a *SessionInputArgs) { a.TargetId = big },
		"upstream address": func(a *SessionInputArgs) { a.UpstreamAddress = big + ":22" },
	} {
		t.Run(name, func(t *testing.T) {
			a := validArgs(t)
			mod(&a)
			msg, err := BuildSessionInput(context.Background(), a)
			require.Error(t, err)
			assert.Nil(t, msg)
		})
	}
}
