// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"net"
	"slices"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/types/known/anypb"
)

func init() {
	if err := proxy.RegisterHandler(proxy.SshHandlerName, handleProxy); err != nil {
		panic(err)
	}
}

// InputDecoder turns the handler argument of a session into the plain values
// HandleSession needs. The proto message that carries them arrives with the
// controller slice; until a decoder is installed every session is refused.
type InputDecoder func(ctx context.Context, df proxy.DecryptFn, pb *anypb.Any) (SessionConfig, []HandleOption, error)

// decodeInput is the installed decoder. The default refuses everything: with
// no decoder there is no host key policy, so nothing may be relayed.
var decodeInput InputDecoder = func(ctx context.Context, _ proxy.DecryptFn, _ *anypb.Any) (SessionConfig, []HandleOption, error) {
	const op = "ssh.defaultDecoder"
	return SessionConfig{}, nil, errors.New(ctx, errors.InvalidParameter, op, "ssh sessions are not yet supported: no session input decoder")
}

// handleProxy adapts the worker proxy Handler contract to HandleSession. It
// refuses the session, before any byte is relayed, when the session input is
// missing, undecodable, or carries no upstream host key policy. The target
// address comes from the decoded (authorized) input, never from the client.
// The ProxyDialer is not used: the ssh client must dial the address its host
// key policy was issued for.
func handleProxy(controlCtx context.Context, dataCtx context.Context, df proxy.DecryptFn, conn net.Conn, _ *proxy.ProxyDialer, connId string, pb *anypb.Any, _ proxy.RecordingManager, _ ...proxy.Option) (proxy.ProxyConnFn, error) {
	const op = "ssh.handleProxy"
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
		return refuse(errors.New(controlCtx, errors.InvalidParameter, op, "missing ssh session input"))
	}
	cfg, opts, err := decodeInput(controlCtx, df, pb)
	if err != nil {
		return refuse(errors.Wrap(controlCtx, err, op, errors.WithMsg("ssh session input unusable"), errors.WithCode(errors.InvalidParameter)))
	}
	if len(cfg.HostKeys.PinnedKeys) == 0 && len(cfg.HostKeys.HostCAs) == 0 {
		return refuse(errors.New(controlCtx, errors.InvalidParameter, op, "empty upstream host key policy"))
	}
	if cfg.Authorization.ConnectionId != connId {
		return refuse(errors.New(controlCtx, errors.InvalidParameter, op, "authorization does not match connection"))
	}
	opts = slices.Clone(opts)
	if cfg.RecordingEnabled {
		// Fail closed: a session that must be recorded is never relayed
		// without a recording factory.
		f := installedRecordingFactory()
		if f == nil {
			return refuse(errors.New(controlCtx, errors.InvalidParameter, op, "recording is required but no recording factory is installed"))
		}
		opts = append(opts, WithRecordingFactory(f), WithRecordingRequired())
	}
	return func() {
		// HandleSession validates again, closes conn and reports refusals.
		_ = HandleSession(dataCtx, conn, cfg, opts...)
	}, nil
}
