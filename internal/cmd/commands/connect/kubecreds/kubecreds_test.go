// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package kubecreds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPair(t *testing.T) (certB64, keyB64 string) {
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

type m = map[string]any

func cfg(mod func(c, u m) m) m {
	cluster := m{"server": "https://k8s.example:6443", "certificate-authority-data": "Q0E=", "tls-server-name": "k8s.internal"}
	user := m{"token": "tok-abc"}
	root := m{
		"clusters":        []any{m{"name": "c1", "cluster": cluster}, m{"name": "other", "cluster": m{"server": "https://x", "certificate-authority-data": "T1RIRVI="}}},
		"users":           []any{m{"name": "u1", "user": user}},
		"contexts":        []any{m{"name": "ctx", "context": m{"cluster": "c1", "user": "u1"}}},
		"current-context": "ctx",
	}
	if mod != nil {
		return mod(cluster, user)
	}
	return root
}

func TestParseValid(t *testing.T) {
	c, k := testPair(t)
	yamlCfg := `
apiVersion: v1
kind: Config
current-context: ctx
clusters:
- name: c1
  cluster: {server: "https://k8s.example:6443", certificate-authority-data: Q0E=}
contexts:
- name: ctx
  context: {cluster: c1, user: u1}
users:
- name: u1
  user: {token: tok-abc}
`
	tests := []struct {
		name string
		in   map[string]any
		want Result
	}{
		{"bearer", m{"token": "tok-abc"}, Result{Shape: ShapeBearerToken, Token: "tok-abc"}},
		{"client cert", m{"client-certificate-data": c, "client-key-data": k}, Result{Shape: ShapeClientCert, ClientCertificateData: c, ClientKeyData: k}},
		{"kubeconfig object", cfg(nil), Result{Shape: ShapeKubeconfig, Token: "tok-abc", Server: "https://k8s.example:6443", CertificateAuthorityData: "Q0E=", TLSServerName: "k8s.internal"}},
		{"kubeconfig yaml string", m{"kubeconfig": yamlCfg}, Result{Shape: ShapeKubeconfig, Token: "tok-abc", Server: "https://k8s.example:6443", CertificateAuthorityData: "Q0E="}},
		{"insecure false is fine", cfg(func(cl, u m) m {
			cl["insecure-skip-tls-verify"] = false
			return withCluster(cl, u)
		}), Result{Shape: ShapeKubeconfig, Token: "tok-abc", Server: "https://k8s.example:6443", CertificateAuthorityData: "Q0E=", TLSServerName: "k8s.internal"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, *got)
		})
	}
}

// withCluster rebuilds a kubeconfig around the given cluster and user maps.
func withCluster(cluster, user m) m {
	return m{
		"clusters":        []any{m{"name": "c1", "cluster": cluster}},
		"users":           []any{m{"name": "u1", "user": user}},
		"contexts":        []any{m{"name": "ctx", "context": m{"cluster": "c1", "user": "u1"}}},
		"current-context": "ctx",
	}
}

func base() (m, m) {
	return m{"server": "https://k8s.example:6443", "certificate-authority-data": "Q0E="}, m{"token": "tok-abc"}
}

func TestParseRejects(t *testing.T) {
	c, k := testPair(t)
	mut := func(f func(cl, u m)) m {
		cl, u := base()
		f(cl, u)
		return withCluster(cl, u)
	}
	tests := []struct {
		name      string
		in        map[string]any
		unsupport bool
	}{
		{"nil", nil, true},
		{"empty", m{}, true},
		{"unknown shape", m{"username": "a", "password": "b"}, true},
		{"token mixed with cert", m{"token": "t", "client-certificate-data": c, "client-key-data": k}, true},
		{"kubeconfig mixed with token", m{"kubeconfig": "x", "token": "t"}, true},
		{"cert without key", m{"client-certificate-data": c}, false},
		{"key without cert", m{"client-key-data": k}, false},
		{"cert not base64", m{"client-certificate-data": "!!", "client-key-data": k}, false},
		{"cert/key not pair", m{"client-certificate-data": c, "client-key-data": base64.StdEncoding.EncodeToString([]byte("nope"))}, false},
		{"empty token", m{"token": ""}, false},
		{"non-string token", m{"token": 5}, false},
		{"token with newline", m{"token": "a\nb"}, false},
		{"token with padding space", m{"token": " a"}, false},
		{"insecure-skip-tls-verify", mut(func(cl, u m) { cl["insecure-skip-tls-verify"] = true }), false},
		{"insecure-skip-tls-verify string", mut(func(cl, u m) { cl["insecure-skip-tls-verify"] = "true" }), false},
		{"CA file path", mut(func(cl, u m) { cl["certificate-authority"] = "/etc/ca.pem" }), false},
		{"proxy-url", mut(func(cl, u m) { cl["proxy-url"] = "http://evil" }), false},
		{"exec user", mut(func(cl, u m) { u["exec"] = m{"command": "sh"} }), false},
		{"auth-provider", mut(func(cl, u m) { u["auth-provider"] = m{"name": "gcp"} }), false},
		{"tokenFile", mut(func(cl, u m) { delete(u, "token"); u["tokenFile"] = "/var/token" }), false},
		{"client-certificate file", mut(func(cl, u m) { u["client-certificate"] = "/c" }), false},
		{"client-key file", mut(func(cl, u m) { u["client-key"] = "/k" }), false},
		{"basic auth user", mut(func(cl, u m) { u["username"] = "a"; u["password"] = "b" }), false},
		{"impersonation", mut(func(cl, u m) { u["as"] = "x"; u["act-as"] = "x" }), false},
		{"user with no creds", mut(func(cl, u m) { delete(u, "token") }), false},
		{"user mixes token and cert", mut(func(cl, u m) { u["client-certificate-data"] = c; u["client-key-data"] = k }), false},
		{"CA data not base64", mut(func(cl, u m) { cl["certificate-authority-data"] = "!!" }), false},
		{"missing current-context", func() m { x := cfg(nil); delete(x, "current-context"); return x }(), false},
		{"unknown current-context", func() m { x := cfg(nil); x["current-context"] = "nope"; return x }(), false},
		{"context references missing cluster", func() m {
			x := cfg(nil)
			x["contexts"] = []any{m{"name": "ctx", "context": m{"cluster": "ghost", "user": "u1"}}}
			return x
		}(), false},
		{"context references missing user", func() m {
			x := cfg(nil)
			x["contexts"] = []any{m{"name": "ctx", "context": m{"cluster": "c1", "user": "ghost"}}}
			return x
		}(), false},
		{"insecure in a non-selected cluster", func() m {
			x := cfg(nil)
			x["clusters"] = append(x["clusters"].([]any), m{"name": "evil", "cluster": m{"server": "https://e", "insecure-skip-tls-verify": true}})
			return x
		}(), false},
		{"exec in a non-selected user", func() m {
			x := cfg(nil)
			x["users"] = append(x["users"].([]any), m{"name": "evil", "user": m{"exec": m{"command": "sh"}}})
			return x
		}(), false},
		{"wrapped kubeconfig with extra fields", m{"kubeconfig": "x", "extra": 1}, true},
		{"wrapped kubeconfig empty", m{"kubeconfig": "  "}, false},
		{"wrapped kubeconfig bad yaml", m{"kubeconfig": "clusters: [unclosed"}, false},
		{"clusters wrong type", m{"clusters": "nope"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			require.Error(t, err)
			assert.Nil(t, got)
			if tt.unsupport {
				assert.ErrorIs(t, err, ErrUnsupportedShape)
			}
		})
	}
}

func TestErrorsDoNotLeakSecrets(t *testing.T) {
	const secret = "SUPERSECRETTOKENVALUE"
	cases := []m{
		{"token": secret + "\n"},
		{"token": secret, "client-key-data": "x"},
		withCluster(m{"server": "s", "insecure-skip-tls-verify": true}, m{"token": secret}),
		withCluster(m{"server": "s"}, m{"token": secret, "exec": m{}}),
		withCluster(m{"server": "s", "certificate-authority-data": "!!"}, m{"token": secret}),
		{"kubeconfig": "token: " + secret + "\nclusters: [unclosed"},
	}
	for _, in := range cases {
		_, err := Parse(in)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), secret)
	}
}

func TestOnlySelectedClusterCAIsHonoured(t *testing.T) {
	got, err := Parse(cfg(nil))
	require.NoError(t, err)
	assert.Equal(t, "Q0E=", got.CertificateAuthorityData, "CA of the selected cluster, not of 'other'")
}
