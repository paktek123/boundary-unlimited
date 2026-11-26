// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package kube

import (
	"bufio"
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRelay_ForwardsClientCredentialsVerbatim checks that the worker relay
// adds TLS toward the API server but does not alter or add request headers:
// the client's own Authorization header (the brokered credential) arrives at
// the API server unchanged and nothing else is injected. Refs #26.
func TestRelay_ForwardsClientCredentialsVerbatim(t *testing.T) {
	var got http.Header
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	p, err := New(context.Background(), Config{Address: srv.Listener.Addr().String(), CAPEM: ca, ServerName: "example.com"})
	require.NoError(t, err)

	c1, c2 := net.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- p.Relay(context.Background(), c2) }()

	_, err = c1.Write([]byte("GET /version HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer fake-client-token\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	r := bufio.NewReader(c1)
	for {
		if _, err := r.ReadString('\n'); err != nil {
			break
		}
	}
	_ = c1.Close()
	require.NoError(t, <-errCh)

	assert.Equal(t, "Bearer fake-client-token", got.Get("Authorization"))
	for h := range got {
		assert.False(t, strings.EqualFold(h, "X-Boundary-Token") || strings.EqualFold(h, "Impersonate-User"), "unexpected header %s", h)
	}
}
