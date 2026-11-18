// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	bsrssh "github.com/hashicorp/boundary/internal/bsr/ssh"
	sshproxy "github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/recguard"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// ErrRecordingSpec is returned for every failure to build a recording spec.
// It never carries key material or session metadata.
var ErrRecordingSpec = errors.New("worker: recording spec unavailable")

// AuthorisedSessionSource returns the controller-authorised metadata of a
// session. It must read only worker state received from the controller, never
// anything supplied by the connecting client. Binding it to the worker's
// session manager happens in the wiring slice.
type AuthorisedSessionSource interface {
	// SessionMeta returns the BSR session metadata for sessionId, or an error
	// if the session is unknown or not authorised for recording.
	SessionMeta(ctx context.Context, sessionId string) (*bsr.SessionMeta, error)
}

// recordingSpecProvider implements sshproxy.SpecProvider. It is not installed
// anywhere yet: the recording factory is wired in a later slice.
type recordingSpecProvider struct {
	wrapper    wrapping.Wrapper
	source     AuthorisedSessionSource
	capacity   int64
	terminator recguard.Terminator
	marker     recguard.Marker
}

var _ sshproxy.SpecProvider = (*recordingSpecProvider)(nil)

// newRecordingSpecProvider returns a provider that creates fresh per-session
// keys wrapped by the worker's bsr-purpose KMS wrapper. Every dependency is
// required (fail closed); capacity must be positive.
func newRecordingSpecProvider(wrapper wrapping.Wrapper, source AuthorisedSessionSource, capacity int64, t recguard.Terminator, m recguard.Marker) (*recordingSpecProvider, error) {
	switch {
	case wrapper == nil:
		return nil, fmt.Errorf("%w: missing bsr kms wrapper", ErrRecordingSpec)
	case source == nil:
		return nil, fmt.Errorf("%w: missing session source", ErrRecordingSpec)
	case capacity <= 0:
		return nil, fmt.Errorf("%w: capacity must be positive", ErrRecordingSpec)
	case t == nil:
		return nil, fmt.Errorf("%w: missing terminator", ErrRecordingSpec)
	case m == nil:
		return nil, fmt.Errorf("%w: missing marker", ErrRecordingSpec)
	}
	return &recordingSpecProvider{wrapper: wrapper, source: source, capacity: capacity, terminator: t, marker: m}, nil
}

// RecordingSpec implements sshproxy.SpecProvider. The identifiers come from
// the Authorization (produced from the controller's session authorisation) and
// the metadata from the authorised-session source; any error refuses the
// session. Errors are fixed values that never echo keys or metadata.
func (p *recordingSpecProvider) RecordingSpec(ctx context.Context, auth sshproxy.Authorization) (sshproxy.SessionRecordingSpec, error) {
	if auth.SessionId == "" || auth.ConnectionId == "" {
		return sshproxy.SessionRecordingSpec{}, fmt.Errorf("%w: incomplete authorization", ErrRecordingSpec)
	}
	sm, err := p.source.SessionMeta(ctx, auth.SessionId)
	if err != nil || sm == nil {
		return sshproxy.SessionRecordingSpec{}, fmt.Errorf("%w: session not authorised for recording", ErrRecordingSpec)
	}
	// Never trust the source to name a different session than the one that
	// was authorised.
	if sm.PublicId != auth.SessionId {
		return sshproxy.SessionRecordingSpec{}, fmt.Errorf("%w: session mismatch", ErrRecordingSpec)
	}
	keys, err := kms.CreateKeys(ctx, p.wrapper, auth.SessionId)
	if err != nil || keys == nil {
		return sshproxy.SessionRecordingSpec{}, fmt.Errorf("%w: key creation failed", ErrRecordingSpec)
	}
	return sshproxy.SessionRecordingSpec{
		Meta:         &bsr.SessionRecordingMeta{Id: auth.SessionId, Protocol: bsrssh.Protocol},
		SessionMeta:  sm,
		Keys:         keys,
		ConnectionId: auth.ConnectionId,
		Capacity:     p.capacity,
		Terminator:   p.terminator,
		Marker:       p.marker,
	}, nil
}
