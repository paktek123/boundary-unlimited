// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func kubeTestPair(t *testing.T) (certB64, keyB64 string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	kb, err := x509.MarshalECPrivateKey(k)
	require.NoError(t, err)
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kp := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return base64.StdEncoding.EncodeToString(c), base64.StdEncoding.EncodeToString(kp)
}

func TestKubeconfigFromCredential(t *testing.T) {
	t.Parallel()
	const sentinelToken = "sentinel-token-9f3a"
	certB64, keyB64 := kubeTestPair(t)
	caB64 := base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"))
	const local = "127.0.0.1:34567"

	fullCfg := func(user map[string]any) map[string]any {
		return map[string]any{
			"clusters": []any{map[string]any{"name": "c1", "cluster": map[string]any{
				"server": "https://k8s.example:6443", "certificate-authority-data": caB64, "tls-server-name": "k8s.internal",
			}}},
			"users":           []any{map[string]any{"name": "u1", "user": user}},
			"contexts":        []any{map[string]any{"name": "ctx", "context": map[string]any{"cluster": "c1", "user": "u1"}}},
			"current-context": "ctx",
		}
	}

	tests := []struct {
		name    string
		cred    map[string]any
		sni     string
		wantErr bool
		check   func(t *testing.T, cluster, user map[string]any)
	}{
		{
			name: "token",
			cred: map[string]any{"token": sentinelToken},
			sni:  "k8s.example.com",
			check: func(t *testing.T, cluster, user map[string]any) {
				assert.Equal(t, sentinelToken, user["token"])
				assert.Equal(t, "k8s.example.com", cluster["tls-server-name"])
				assert.NotContains(t, cluster, "certificate-authority-data")
			},
		},
		{
			name: "client cert",
			cred: map[string]any{"client-certificate-data": certB64, "client-key-data": keyB64},
			sni:  "k8s.example.com",
			check: func(t *testing.T, cluster, user map[string]any) {
				assert.Equal(t, certB64, user["client-certificate-data"])
				assert.Equal(t, keyB64, user["client-key-data"])
			},
		},
		{
			name: "full kubeconfig token, server rewritten, ca and sni carried",
			cred: fullCfg(map[string]any{"token": sentinelToken}),
			check: func(t *testing.T, cluster, user map[string]any) {
				assert.Equal(t, "https://"+local, cluster["server"])
				assert.Equal(t, caB64, cluster["certificate-authority-data"])
				assert.Equal(t, "k8s.internal", cluster["tls-server-name"])
				assert.Equal(t, sentinelToken, user["token"])
			},
		},
		{
			name: "full kubeconfig client cert, explicit sni wins",
			cred: fullCfg(map[string]any{"client-certificate-data": certB64, "client-key-data": keyB64}),
			sni:  "override.example.com",
			check: func(t *testing.T, cluster, user map[string]any) {
				assert.Equal(t, "override.example.com", cluster["tls-server-name"])
				assert.Equal(t, certB64, user["client-certificate-data"])
			},
		},
		{name: "unsupported shape", cred: map[string]any{"foo": "bar"}, sni: "x", wantErr: true},
		{name: "empty credential", cred: map[string]any{}, sni: "x", wantErr: true},
		{
			name:    "exec kubeconfig",
			cred:    fullCfg(map[string]any{"exec": map[string]any{"command": "sh", "token": sentinelToken}}),
			wantErr: true,
		},
		{
			name:    "insecure-skip-tls-verify kubeconfig",
			cred:    map[string]any{"clusters": []any{map[string]any{"name": "c1", "cluster": map[string]any{"server": "https://x", "insecure-skip-tls-verify": true}}}, "users": []any{map[string]any{"name": "u1", "user": map[string]any{"token": sentinelToken}}}, "contexts": []any{map[string]any{"name": "ctx", "context": map[string]any{"cluster": "c1", "user": "u1"}}}, "current-context": "ctx"},
			sni:     "x",
			wantErr: true,
		},
		{name: "token without sni", cred: map[string]any{"token": sentinelToken}, wantErr: true},
		{name: "bad local address", cred: map[string]any{"token": sentinelToken}, sni: "x", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := local
			if tc.name == "bad local address" {
				addr = "nonsense"
			}
			path, cleanup, err := kubeconfigFromCredential(tc.cred, addr, tc.sni)
			if tc.wantErr {
				require.Error(t, err)
				assert.Empty(t, path)
				assert.Nil(t, cleanup)
				for _, secret := range []string{sentinelToken, certB64, keyB64} {
					assert.NotContains(t, err.Error(), secret)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cleanup)

			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "insecure-skip-tls-verify")
			require.NoError(t, rejectExecKubeconfig(raw))

			var doc struct {
				Clusters []struct {
					Cluster map[string]any `yaml:"cluster"`
				} `yaml:"clusters"`
				Users []struct {
					User map[string]any `yaml:"user"`
				} `yaml:"users"`
			}
			require.NoError(t, yaml.Unmarshal(raw, &doc))
			require.Len(t, doc.Clusters, 1)
			require.Len(t, doc.Users, 1)
			assert.Equal(t, "https://"+local, doc.Clusters[0].Cluster["server"])
			tc.check(t, doc.Clusters[0].Cluster, doc.Users[0].User)

			fi, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

			require.NoError(t, cleanup())
			_, err = os.Stat(path)
			assert.True(t, os.IsNotExist(err))
		})
	}
}
