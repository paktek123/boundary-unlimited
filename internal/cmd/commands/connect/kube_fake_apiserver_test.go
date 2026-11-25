// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package connect

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestKubeconfigFromCredential_FakeAPIServer is a kind-free end-to-end check
// of the client half of `boundary connect kube` (Refs #339): a brokered
// credential becomes a private kubeconfig that points at the local proxy
// address, and a client built from that kubeconfig verifies the (fake) API
// server certificate and presents the brokered token. No Docker, database or
// cluster is involved.
func TestKubeconfigFromCredential_FakeAPIServer(t *testing.T) {
	t.Parallel()
	const token = "fake-brokered-token"

	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	cred := map[string]any{
		"clusters": []any{map[string]any{"name": "c1", "cluster": map[string]any{
			"server": "https://k8s.example:6443", "certificate-authority-data": base64.StdEncoding.EncodeToString(caPEM),
		}}},
		"users":           []any{map[string]any{"name": "u1", "user": map[string]any{"token": token}}},
		"contexts":        []any{map[string]any{"name": "ctx", "context": map[string]any{"cluster": "c1", "user": "u1"}}},
		"current-context": "ctx",
	}

	addr := srv.Listener.Addr().String()
	// example.com is one of the SANs of the httptest certificate.
	path, cleanup, err := kubeconfigFromCredential(cred, addr, "example.com")
	require.NoError(t, err)
	t.Cleanup(func() { _ = cleanup() })

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
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
	cl := doc.Clusters[0].Cluster
	assert.Equal(t, "https://"+addr, cl["server"], "server must be rewritten to the local proxy address")
	assert.NotContains(t, cl, "insecure-skip-tls-verify")

	caData, err := base64.StdEncoding.DecodeString(cl["certificate-authority-data"].(string))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caData))

	newClient := func(p *x509.CertPool, serverName string) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p, ServerName: serverName, MinVersion: tls.VersionTLS12}}}
	}

	// Verified connection with the brokered token.
	req, err := http.NewRequest(http.MethodGet, cl["server"].(string)+"/version", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+doc.Users[0].User["token"].(string))
	resp, err := newClient(pool, cl["tls-server-name"].(string)).Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, "Bearer "+token, gotAuth)

	// An unrelated CA must be refused: verification is never disabled.
	bad, err := newClient(x509.NewCertPool(), "example.com").Get(cl["server"].(string) + "/version")
	if bad != nil {
		_ = bad.Body.Close()
	}
	assert.Error(t, err)
}
