// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const testToken = "s3cr3t-token-value"

func TestBuildKubeconfig(t *testing.T) {
	t.Parallel()
	ca := []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n")
	cert := []byte("-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n")
	key := []byte("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n")

	t.Run("token with ca", func(t *testing.T) {
		out, err := buildKubeconfig(kubeconfigInput{
			ProxyAddr: "127.0.0.1:34567", TLSServerName: "k8s.example.com", CACertPEM: ca, Token: testToken,
		})
		require.NoError(t, err)
		var doc map[string]any
		require.NoError(t, yaml.Unmarshal(out, &doc))
		assert.Equal(t, "Config", doc["kind"])
		assert.Equal(t, "boundary", doc["current-context"])
		cl := doc["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)
		assert.Equal(t, "https://127.0.0.1:34567", cl["server"])
		assert.Equal(t, "k8s.example.com", cl["tls-server-name"])
		assert.Equal(t, base64.StdEncoding.EncodeToString(ca), cl["certificate-authority-data"])
		assert.NotContains(t, cl, "insecure-skip-tls-verify")
		u := doc["users"].([]any)[0].(map[string]any)["user"].(map[string]any)
		assert.Equal(t, testToken, u["token"])
	})
	t.Run("client cert without ca", func(t *testing.T) {
		out, err := buildKubeconfig(kubeconfigInput{
			ProxyAddr: "[::1]:1234", TLSServerName: "k8s", ClientCertPEM: cert, ClientKeyPEM: key,
		})
		require.NoError(t, err)
		var doc map[string]any
		require.NoError(t, yaml.Unmarshal(out, &doc))
		cl := doc["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)
		assert.Equal(t, "https://[::1]:1234", cl["server"])
		assert.NotContains(t, cl, "certificate-authority-data")
		u := doc["users"].([]any)[0].(map[string]any)["user"].(map[string]any)
		assert.Equal(t, base64.StdEncoding.EncodeToString(cert), u["client-certificate-data"])
		assert.Equal(t, base64.StdEncoding.EncodeToString(key), u["client-key-data"])
		assert.NotContains(t, u, "token")
	})

	tests := []struct {
		name string
		in   kubeconfigInput
	}{
		{"bad addr", kubeconfigInput{ProxyAddr: "localhost", TLSServerName: "k", Token: testToken}},
		{"bad port", kubeconfigInput{ProxyAddr: "127.0.0.1:99999", TLSServerName: "k", Token: testToken}},
		{"no server name", kubeconfigInput{ProxyAddr: "127.0.0.1:1", Token: testToken}},
		{"no auth", kubeconfigInput{ProxyAddr: "127.0.0.1:1", TLSServerName: "k"}},
		{"both auth", kubeconfigInput{ProxyAddr: "127.0.0.1:1", TLSServerName: "k", Token: testToken, ClientCertPEM: cert, ClientKeyPEM: key}},
		{"cert without key", kubeconfigInput{ProxyAddr: "127.0.0.1:1", TLSServerName: "k", ClientCertPEM: cert}},
		{"key without cert", kubeconfigInput{ProxyAddr: "127.0.0.1:1", TLSServerName: "k", ClientKeyPEM: key}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := buildKubeconfig(tc.in)
			require.Error(t, err)
			assert.Nil(t, out)
			assert.NotContains(t, err.Error(), testToken)
			assert.NotContains(t, err.Error(), "PRIVATE KEY")
		})
	}
}

func TestRejectExecKubeconfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		doc     string
		wantErr bool
	}{
		{"token user", "users:\n- name: a\n  user:\n    token: " + testToken + "\n", false},
		{"exec user", "users:\n- name: a\n  user:\n    exec:\n      command: /bin/sh\n", true},
		{"second user exec", "users:\n- name: a\n  user:\n    token: x\n- name: b\n  user:\n    exec:\n      command: x\n", true},
		{"auth provider", "users:\n- name: a\n  user:\n    auth-provider:\n      name: gcp\n", true},
		{"invalid yaml", "users: [: " + testToken, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := rejectExecKubeconfig([]byte(tc.doc))
			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.NotContains(t, err.Error(), testToken)
		})
	}
}

func TestWriteKubeconfigTemp(t *testing.T) {
	t.Parallel()
	content := []byte("kind: Config\n")
	path, cleanup, err := writeKubeconfigTemp(content)
	require.NoError(t, err)
	require.NotNil(t, cleanup)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, got)

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
		di, err := os.Stat(filepath.Dir(path))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())
	}

	require.NoError(t, cleanup())
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Dir(path))
	assert.True(t, os.IsNotExist(err))

	// Each call gets a fresh directory.
	p2, c2, err := writeKubeconfigTemp(content)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c2() })
	assert.NotEqual(t, filepath.Dir(path), filepath.Dir(p2))
}
