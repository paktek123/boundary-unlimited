// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package kube

import (
	"context"
	"net"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/types/known/anypb"
)

func init() {
	if err := proxy.RegisterHandler(proxy.KubernetesHandlerName, handleProxy); err != nil {
		panic(err)
	}
}

// SessionConfig is what the handler needs to relay one session: the verified
// API server settings and the id of the connection the controller authorized.
type SessionConfig struct {
	Config
	ConnectionId string
}

// InputDecoder turns the handler argument of a session into a SessionConfig.
// The proto message that carries the target data arrives with the controller
// slice; until a decoder is installed every session is refused.
type InputDecoder func(ctx context.Context, df proxy.DecryptFn, pb *anypb.Any) (SessionConfig, error)

// decodeInput is the installed decoder. The default refuses everything: with
// no decoder there is no CA and no server name, so nothing may be relayed.
var decodeInput InputDecoder = func(ctx context.Context, _ proxy.DecryptFn, _ *anypb.Any) (SessionConfig, error) {
	const op = "kube.defaultDecoder"
	return SessionConfig{}, errors.New(ctx, errors.InvalidParameter, op, "kubernetes sessions are not yet supported: no session input decoder")
}

// handleProxy adapts the worker proxy Handler contract to Proxy.Relay. It
// refuses the session, before any byte is relayed, when the input is missing,
// undecodable, lacks a CA or server name (kube.New requires them), or does not
// match the connection. The API server address comes from the decoded
// (authorized) input, never from the client.
func handleProxy(controlCtx context.Context, dataCtx context.Context, df proxy.DecryptFn, conn net.Conn, _ *proxy.ProxyDialer, connId string, pb *anypb.Any, _ proxy.RecordingManager, _ ...proxy.Option) (proxy.ProxyConnFn, error) {
	const op = "kube.handleProxy"
	if conn == nil {
		return nil, errors.New(controlCtx, errors.InvalidParameter, op, "conn is nil")
	}
	refuse := func(err error) (proxy.ProxyConnFn, error) {
		_ = conn.Close()
		return nil, err
	}
	switch {
	case connId == "":
		return refuse(errors.New(controlCtx, errors.InvalidParameter, op, "connection id is empty"))
	case pb == nil:
		return refuse(errors.New(controlCtx, errors.InvalidParameter, op, "missing kubernetes session input"))
	}
	cfg, err := decodeInput(controlCtx, df, pb)
	if err != nil {
		return refuse(errors.Wrap(controlCtx, err, op, errors.WithMsg("kubernetes session input unusable"), errors.WithCode(errors.InvalidParameter)))
	}
	if cfg.ConnectionId != connId {
		return refuse(errors.New(controlCtx, errors.InvalidParameter, op, "authorization does not match connection"))
	}
	p, err := New(controlCtx, cfg.Config)
	if err != nil {
		return refuse(errors.Wrap(controlCtx, err, op, errors.WithMsg("kubernetes session input invalid"), errors.WithCode(errors.InvalidParameter)))
	}
	return func() {
		// Relay closes conn; a TLS verification failure relays nothing.
		_ = p.Relay(dataCtx, conn)
	}, nil
}
