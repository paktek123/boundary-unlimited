// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"net"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/target/ssh/hostkeypolicy"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// maxSessionInputFieldLength mirrors the worker decoder's bound on ids and
// the address.
const maxSessionInputFieldLength = 256

// SessionInputArgs are the values from which the worker handler argument of an
// ssh session is built. It deliberately has no credential field.
type SessionInputArgs struct {
	SessionId        string
	ConnectionId     string
	TargetId         string
	UpstreamAddress  string // host:port, resolved by the controller
	PinnedHostKeys   []string
	HostCAs          []string
	RecordingEnabled bool
	Expiration       time.Time
}

// BuildSessionInput builds the SshSessionInput worker handler argument and
// wraps it as the protocol context value. It fails closed: a missing id, a
// bad address, an expiration that is unset, an empty host key policy (no TOFU,
// no other source of trust) or an invalid policy all return an error and no
// message. Error text is a fixed reason and never contains key material. It
// is not called by AuthorizeSession yet, so nothing is enabled by it.
func BuildSessionInput(ctx context.Context, a SessionInputArgs) (*anypb.Any, error) {
	const op = "ssh.BuildSessionInput"
	fail := func(msg string) (*anypb.Any, error) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, msg)
	}
	for _, s := range []string{a.SessionId, a.ConnectionId, a.TargetId, a.UpstreamAddress} {
		if len(s) > maxSessionInputFieldLength {
			return fail("ssh session input field is too large")
		}
	}
	switch {
	case a.SessionId == "":
		return fail("ssh session input has no session id")
	case a.ConnectionId == "":
		return fail("ssh session input has no connection id")
	case a.TargetId == "":
		return fail("ssh session input has no target id")
	}
	if _, port, err := net.SplitHostPort(a.UpstreamAddress); err != nil || port == "" {
		return fail("ssh session input upstream address must be host:port")
	}
	if len(a.PinnedHostKeys)+len(a.HostCAs) == 0 {
		return fail("ssh target has no host key policy")
	}
	if len(a.PinnedHostKeys)+len(a.HostCAs) > hostkeypolicy.MaxHostKeys {
		return fail("ssh host key policy has too many entries")
	}
	if err := hostkeypolicy.ValidateHostKeys(a.PinnedHostKeys); err != nil {
		return fail("ssh host key policy is invalid")
	}
	for _, ca := range a.HostCAs {
		if err := hostkeypolicy.ValidateHostCA(ca); err != nil {
			return fail("ssh host key policy is invalid")
		}
	}
	if a.Expiration.IsZero() {
		return fail("ssh session input has no expiration")
	}
	in := &services.SshSessionInput{
		SessionId:        a.SessionId,
		ConnectionId:     a.ConnectionId,
		TargetId:         a.TargetId,
		UpstreamAddress:  a.UpstreamAddress,
		PinnedHostKeys:   append([]string(nil), a.PinnedHostKeys...),
		HostCas:          append([]string(nil), a.HostCAs...),
		RecordingEnabled: a.RecordingEnabled,
		Expiration:       timestamppb.New(a.Expiration),
	}
	msg, err := anypb.New(in)
	if err != nil {
		return fail("ssh session input could not be encoded")
	}
	return msg, nil
}
