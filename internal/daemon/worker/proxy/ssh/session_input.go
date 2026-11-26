// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/hostkey"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/target/ssh/hostkeypolicy"
	"google.golang.org/protobuf/types/known/anypb"
)

// maxSessionInputIdLength bounds the id and address strings of the input.
const maxSessionInputIdLength = 256

var decoderMu sync.RWMutex

// InstallSessionInputDecoder installs DecodeSessionInput as the decoder of the
// registered ssh handler. It is called at worker startup. Until it is called
// every ssh session is refused.
func InstallSessionInputDecoder() { SetInputDecoder(DecodeSessionInput) }

// SetInputDecoder replaces the installed decoder. Passing nil restores the
// default decoder, which refuses every session.
func SetInputDecoder(d InputDecoder) {
	decoderMu.Lock()
	defer decoderMu.Unlock()
	if d == nil {
		d = refuseAll
	}
	decodeInput = d
}

func refuseAll(ctx context.Context, _ proxy.DecryptFn, _ *anypb.Any) (SessionConfig, []HandleOption, error) {
	const op = "ssh.defaultDecoder"
	return SessionConfig{}, nil, errors.New(ctx, errors.InvalidParameter, op, "ssh sessions are not yet supported: no session input decoder")
}

// DecodeSessionInput maps an SshSessionInput to a SessionConfig. It refuses a
// missing or wrongly typed message, an empty host key policy, an empty or
// oversized id or address, and an invalid host key policy. Errors are fixed
// reasons and never carry key material. The message holds no credential, so a
// session that needs an injected credential cannot be authenticated upstream:
// the zero credential is rejected when the session starts.
func DecodeSessionInput(ctx context.Context, _ proxy.DecryptFn, pb *anypb.Any) (SessionConfig, []HandleOption, error) {
	const op = "ssh.DecodeSessionInput"
	fail := func(msg string) (SessionConfig, []HandleOption, error) {
		return SessionConfig{}, nil, errors.New(ctx, errors.InvalidParameter, op, msg)
	}
	if pb == nil {
		return fail("missing ssh session input")
	}
	in := &services.SshSessionInput{}
	if !pb.MessageIs(in) {
		return fail("ssh session input has the wrong type")
	}
	if err := pb.UnmarshalTo(in); err != nil {
		return fail("ssh session input is undecodable")
	}
	for _, s := range []string{in.GetSessionId(), in.GetConnectionId(), in.GetTargetId(), in.GetUpstreamAddress()} {
		if len(s) > maxSessionInputIdLength {
			return fail("ssh session input field is too large")
		}
	}
	switch {
	case in.GetSessionId() == "":
		return fail("ssh session input has no session id")
	case in.GetConnectionId() == "":
		return fail("ssh session input has no connection id")
	case in.GetUpstreamAddress() == "":
		return fail("ssh session input has no upstream address")
	}
	if _, port, err := net.SplitHostPort(in.GetUpstreamAddress()); err != nil || port == "" {
		return fail("ssh session input upstream address must be host:port")
	}
	if len(in.GetPinnedHostKeys())+len(in.GetHostCas()) == 0 {
		return fail("ssh session input has an empty host key policy")
	}
	if len(in.GetPinnedHostKeys())+len(in.GetHostCas()) > hostkeypolicy.MaxHostKeys {
		return fail("ssh session input host key policy has too many entries")
	}
	policy := hostkey.Policy{PinnedKeys: in.GetPinnedHostKeys(), HostCAs: in.GetHostCas()}
	if err := hostkey.Validate(policy); err != nil {
		return fail("ssh session input host key policy is invalid")
	}
	if in.GetExpiration() == nil || !in.GetExpiration().IsValid() {
		return fail("ssh session input has no valid expiration")
	}
	key, err := hostkey.Generate(ctx)
	if err != nil {
		return fail("could not generate the client-facing host key")
	}
	return SessionConfig{
		Authorization: Authorization{
			SessionId:    in.GetSessionId(),
			ConnectionId: in.GetConnectionId(),
			Expiry:       in.GetExpiration().AsTime().Truncate(time.Nanosecond),
		},
		ClientHostKey:    key.Signer,
		UpstreamAddr:     in.GetUpstreamAddress(),
		HostKeys:         policy,
		TargetId:         in.GetTargetId(),
		RecordingEnabled: in.GetRecordingEnabled(),
	}, nil, nil
}
