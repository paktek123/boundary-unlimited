// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package kube

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func setDecoder(t *testing.T, d InputDecoder) {
	t.Helper()
	old := decodeInput
	decodeInput = d
	t.Cleanup(func() { decodeInput = old })
}

func anyMsg(t *testing.T) *anypb.Any {
	t.Helper()
	a, err := anypb.New(&emptypb.Empty{})
	require.NoError(t, err)
	return a
}

func closed(t *testing.T, c net.Conn) bool {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := c.Read(make([]byte, 1))
	return err == io.EOF
}

func TestHandlerRegistered(t *testing.T) {
	require.Error(t, proxy.RegisterHandler(proxy.KubernetesHandlerName, handleProxy), "already registered by init")
}

func TestHandleProxyRefuses(t *testing.T) {
	addr, ca := fakeAPIServer(t)
	good := SessionConfig{Config: Config{Address: addr, CAPEM: ca, ServerName: "example.com"}, ConnectionId: "sc_1"}
	tests := []struct {
		name    string
		decoder InputDecoder
		connId  string
		pb      *anypb.Any
	}{
		{"default decoder refuses", nil, "sc_1", anyMsg(t)},
		{"missing input", nil, "sc_1", nil},
		{"empty connection id", func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, error) { return good, nil }, "", anyMsg(t)},
		{"connection mismatch", func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, error) { return good, nil }, "sc_other", anyMsg(t)},
		{"no CA", func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, error) {
			c := good
			c.CAPEM = nil
			return c, nil
		}, "sc_1", anyMsg(t)},
		{"no server name", func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, error) {
			c := good
			c.ServerName = ""
			return c, nil
		}, "sc_1", anyMsg(t)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.decoder != nil {
				setDecoder(t, tt.decoder)
			}
			server, client := net.Pipe()
			defer server.Close()
			fn, err := handleProxy(context.Background(), context.Background(), nil, client, nil, tt.connId, tt.pb, nil)
			require.Error(t, err)
			assert.Nil(t, fn)
			assert.True(t, closed(t, server), "client connection must be closed")
		})
	}
}

func TestHandleProxyRelays(t *testing.T) {
	addr, ca := fakeAPIServer(t)
	setDecoder(t, func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, error) {
		return SessionConfig{Config: Config{Address: addr, CAPEM: ca, ServerName: "example.com"}, ConnectionId: "sc_1"}, nil
	})
	server, client := net.Pipe()
	defer server.Close()
	fn, err := handleProxy(context.Background(), context.Background(), nil, client, nil, "sc_1", anyMsg(t), nil)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	_, err = server.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)
	b, _ := io.ReadAll(server)
	assert.Contains(t, string(b), "ok")
	<-done
}
