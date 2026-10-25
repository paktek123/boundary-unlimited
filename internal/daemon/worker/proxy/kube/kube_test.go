// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package kube

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAPIServer starts a TLS server for 127.0.0.1/example.com that answers any
// HTTP request with "ok", returning its address and CA PEM.
func fakeAPIServer(t *testing.T) (addr string, caPEM []byte) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return srv.Listener.Addr().String(), caPEM
}

func otherCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "other-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestNew_Invalid(t *testing.T) {
	addr, ca := fakeAPIServer(t)
	tests := []struct {
		name string
		cfg  Config
	}{
		{"no address", Config{CAPEM: ca, ServerName: "example.com"}},
		{"bad address", Config{Address: "nohostport", CAPEM: ca, ServerName: "example.com"}},
		{"no server name", Config{Address: addr, CAPEM: ca}},
		{"no ca", Config{Address: addr, ServerName: "example.com"}},
		{"unparsable ca", Config{Address: addr, CAPEM: []byte("junk"), ServerName: "example.com"}},
		{"cert without key", Config{Address: addr, CAPEM: ca, ServerName: "example.com", ClientCertPEM: ca}},
		{"bad keypair", Config{Address: addr, CAPEM: ca, ServerName: "example.com", ClientCertPEM: ca, ClientKeyPEM: []byte("SECRETKEYDATA")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(context.Background(), tc.cfg)
			require.Error(t, err)
			assert.Nil(t, p)
			assert.NotContains(t, err.Error(), "SECRETKEYDATA")
		})
	}
}

func TestRelay_Success(t *testing.T) {
	addr, ca := fakeAPIServer(t)
	p, err := New(context.Background(), Config{Address: addr, CAPEM: ca, ServerName: "example.com"})
	require.NoError(t, err)

	// The fake server cert is valid for example.com, so verification passes.
	c1, c2 := net.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- p.Relay(context.Background(), c2) }()

	// The client leg is plaintext; the relay adds TLS toward the API server.
	tc := c1
	_, err = tc.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	var sb strings.Builder
	r := bufio.NewReader(tc)
	for {
		line, err := r.ReadString('\n')
		sb.WriteString(line)
		if err != nil {
			break
		}
	}
	assert.Contains(t, sb.String(), "200 OK")
	assert.True(t, strings.HasSuffix(sb.String(), "ok"))
	_ = tc.Close()
	require.NoError(t, <-errCh)
	assert.Zero(t, p.ActiveConnections())
	in, out := p.BytesRelayed()
	assert.Positive(t, in)
	assert.Positive(t, out)
}

func TestRelay_VerificationFailures(t *testing.T) {
	addr, ca := fakeAPIServer(t)
	tests := []struct {
		name string
		cfg  Config
	}{
		{"wrong ca", Config{Address: addr, CAPEM: otherCA(t), ServerName: "example.com"}},
		{"wrong server name", Config{Address: addr, CAPEM: ca, ServerName: "wrong.invalid"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(context.Background(), tc.cfg)
			require.NoError(t, err)
			c1, c2 := net.Pipe()
			defer c1.Close()
			err = p.Relay(context.Background(), c2)
			require.Error(t, err)
			in, out := p.BytesRelayed()
			assert.Zero(t, in+out)
			assert.Zero(t, p.ActiveConnections())
			// the client side was closed: reads fail.
			_ = c1.SetReadDeadline(time.Now().Add(time.Second))
			_, rerr := c1.Read(make([]byte, 1))
			assert.Error(t, rerr)
		})
	}
}

func TestRelay_NilClient(t *testing.T) {
	addr, ca := fakeAPIServer(t)
	p, err := New(context.Background(), Config{Address: addr, CAPEM: ca, ServerName: "example.com"})
	require.NoError(t, err)
	require.Error(t, p.Relay(context.Background(), nil))
}

func TestRelay_ContextCancelNoLeak(t *testing.T) {
	addr, ca := fakeAPIServer(t)
	p, err := New(context.Background(), Config{Address: addr, CAPEM: ca, ServerName: "example.com"})
	require.NoError(t, err)

	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	c1, c2 := net.Pipe()
	defer c1.Close()
	errCh := make(chan error, 1)
	go func() { errCh <- p.Relay(ctx, c2) }()
	require.Eventually(t, func() bool { return p.ActiveConnections() == 1 }, 5*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return after cancel")
	}
	assert.Zero(t, p.ActiveConnections())
	require.Eventually(t, func() bool { return runtime.NumGoroutine() <= before+1 }, 5*time.Second, 20*time.Millisecond)
}
