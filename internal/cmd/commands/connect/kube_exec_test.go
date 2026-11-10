// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package connect

import (
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func jsonCred(decoded map[string]any) *targets.SessionCredential {
	return &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{CredentialType: "json"},
		Secret:           &targets.SessionSecret{Decoded: decoded},
	}
}

func TestPrepareKubeconfig(t *testing.T) {
	const sentinel = "tok-sentinel-1234"
	const local = "127.0.0.1:45000"

	t.Run("no json credential keeps flag behaviour", func(t *testing.T) {
		f := &kubeFlags{flagKubeScheme: "https"}
		other := &targets.SessionCredential{CredentialSource: &targets.CredentialSource{CredentialType: "username_password"}}
		in, err := f.prepareKubeconfig("tcp://k8s.example.com:6443", local, []*targets.SessionCredential{other})
		require.NoError(t, err)
		assert.Nil(t, in)
	})
	t.Run("token credential writes private kubeconfig", func(t *testing.T) {
		f := &kubeFlags{flagKubeScheme: "https"}
		c := jsonCred(map[string]any{"token": sentinel})
		in, err := f.prepareKubeconfig("tcp://k8s.example.com:6443", local, []*targets.SessionCredential{c})
		require.NoError(t, err)
		require.NotNil(t, in)
		assert.Same(t, c, in.Used)
		require.Len(t, in.Env, 1)
		path := strings.TrimPrefix(in.Env[0], "KUBECONFIG=")
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Contains(t, string(b), "https://"+local)
		assert.Contains(t, string(b), "k8s.example.com")
		assert.NotContains(t, string(b), "insecure-skip-tls-verify")
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
		require.NoError(t, in.Cleanup())
		_, err = os.Stat(path)
		assert.True(t, os.IsNotExist(err))
	})
	t.Run("client certificate credential", func(t *testing.T) {
		certB64, keyB64 := kubeTestPair(t)
		f := &kubeFlags{flagKubeScheme: "https"}
		in, err := f.prepareKubeconfig("tcp://k8s.example.com:6443", local, []*targets.SessionCredential{
			jsonCred(map[string]any{"client-certificate-data": certB64, "client-key-data": keyB64}),
		})
		require.NoError(t, err)
		defer func() { _ = in.Cleanup() }()
		b, err := os.ReadFile(strings.TrimPrefix(in.Env[0], "KUBECONFIG="))
		require.NoError(t, err)
		assert.Contains(t, string(b), "client-certificate-data")
		assert.NotContains(t, string(b), "insecure-skip-tls-verify")
	})
	t.Run("kubeconfig-shaped credential has server rewritten", func(t *testing.T) {
		f := &kubeFlags{flagKubeScheme: "https"}
		full := map[string]any{
			"clusters": []any{map[string]any{"name": "c1", "cluster": map[string]any{
				"server": "https://upstream.example:6443", "tls-server-name": "k8s.internal",
			}}},
			"users":           []any{map[string]any{"name": "u1", "user": map[string]any{"token": sentinel}}},
			"contexts":        []any{map[string]any{"name": "ctx", "context": map[string]any{"cluster": "c1", "user": "u1"}}},
			"current-context": "ctx",
		}
		in, err := f.prepareKubeconfig("tcp://k8s.example.com:6443", local, []*targets.SessionCredential{jsonCred(full)})
		require.NoError(t, err)
		defer func() { _ = in.Cleanup() }()
		b, err := os.ReadFile(strings.TrimPrefix(in.Env[0], "KUBECONFIG="))
		require.NoError(t, err)
		assert.Contains(t, string(b), "https://"+local)
		assert.NotContains(t, string(b), "upstream.example")
	})
	t.Run("host flag overrides endpoint for server name", func(t *testing.T) {
		f := &kubeFlags{flagKubeScheme: "https", flagKubeHost: "override.example.com"}
		in, err := f.prepareKubeconfig("tcp://k8s.example.com:6443", local, []*targets.SessionCredential{jsonCred(map[string]any{"token": sentinel})})
		require.NoError(t, err)
		defer func() { _ = in.Cleanup() }()
		b, err := os.ReadFile(strings.TrimPrefix(in.Env[0], "KUBECONFIG="))
		require.NoError(t, err)
		assert.Contains(t, string(b), "override.example.com")
	})
	t.Run("fail closed", func(t *testing.T) {
		tests := []struct {
			name  string
			flags kubeFlags
			ep    string
			creds []*targets.SessionCredential
		}{
			{"http scheme", kubeFlags{flagKubeScheme: "http"}, "tcp://k8s.example.com:6443", []*targets.SessionCredential{jsonCred(map[string]any{"token": sentinel})}},
			{"two json credentials", kubeFlags{flagKubeScheme: "https"}, "tcp://k8s.example.com:6443", []*targets.SessionCredential{jsonCred(map[string]any{"token": sentinel}), jsonCred(map[string]any{"token": sentinel})}},
			{"no server name", kubeFlags{flagKubeScheme: "https"}, "", []*targets.SessionCredential{jsonCred(map[string]any{"token": sentinel})}},
			{"unsupported shape", kubeFlags{flagKubeScheme: "https"}, "tcp://k8s.example.com:6443", []*targets.SessionCredential{jsonCred(map[string]any{"foo": "bar"})}},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				in, err := tc.flags.prepareKubeconfig(tc.ep, local, tc.creds)
				require.Error(t, err)
				assert.Nil(t, in)
				assert.NotContains(t, err.Error(), sentinel)
			})
		}
	})
}
