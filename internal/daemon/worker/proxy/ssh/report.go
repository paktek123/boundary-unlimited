// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"fmt"
	"time"

	berrors "github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
)

// Fixed reason codes passed to Reporter.SessionRejected. They carry no
// session-specific data.
const (
	ReasonInvalidAuthorization = "invalid_authorization"
	ReasonMissingClientHostKey = "missing_client_host_key"
	ReasonMissingUpstreamAddr  = "missing_upstream_address"
	ReasonEmptyHostKeyPolicy   = "empty_host_key_policy"
	ReasonInvalidHostKeyPolicy = "invalid_host_key_policy"
	ReasonInvalidSessionPolicy = "invalid_session_policy"
	ReasonInvalidCredential    = "invalid_credential"
	ReasonRecordingUnavailable = "recording_unavailable"
)

// Reporter receives security-relevant events from HandleSession. Values
// passed to it never contain key material, credentials or upstream
// addresses: only the target id, a SHA256 host key fingerprint or one of the
// Reason* codes. A nil Reporter in SessionConfig is a no-op.
type Reporter interface {
	// HostKeyFailure is called once when the key presented by the target is
	// not trusted by the host key policy. fingerprint is the SHA256
	// fingerprint of the presented key.
	HostKeyFailure(ctx context.Context, targetID, fingerprint string)
	// SessionRejected is called when a session is refused before any
	// connection to the target is attempted. reason is a Reason* code.
	SessionRejected(ctx context.Context, targetID, reason string)
}

type noopReporter struct{}

func (noopReporter) HostKeyFailure(context.Context, string, string)  {}
func (noopReporter) SessionRejected(context.Context, string, string) {}

// reportTimeout bounds how long HandleSession waits for a Reporter call. A
// slow or panicking Reporter must not prevent the session from being refused.
var reportTimeout = 2 * time.Second

// safeReporter wraps a Reporter so that a panic is contained and a call that
// takes longer than reportTimeout is abandoned.
type safeReporter struct{ r Reporter }

func newSafeReporter(r Reporter) safeReporter {
	if r == nil {
		r = noopReporter{}
	}
	return safeReporter{r: r}
}

func (s safeReporter) call(ctx context.Context, fn func(context.Context, Reporter)) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reportTimeout)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				event.WriteError(ctx, "ssh.safeReporter.call", fmt.Errorf("reporter panic: %v", r))
			}
		}()
		fn(ctx, s.r)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (s safeReporter) HostKeyFailure(ctx context.Context, targetID, fingerprint string) {
	s.call(ctx, func(ctx context.Context, r Reporter) { r.HostKeyFailure(ctx, targetID, fingerprint) })
}

func (s safeReporter) SessionRejected(ctx context.Context, targetID, reason string) {
	s.call(ctx, func(ctx context.Context, r Reporter) { r.SessionRejected(ctx, targetID, reason) })
}

// NewEventReporter returns a Reporter that writes observation events through
// internal/event. Failures to write are reported as error events.
func NewEventReporter() Reporter { return eventReporter{} }

type eventReporter struct{}

func (eventReporter) HostKeyFailure(ctx context.Context, targetID, fingerprint string) {
	const op = "ssh.eventReporter.HostKeyFailure"
	// Headers, not details: details are dropped when telemetry is disabled.
	if err := event.WriteObservation(ctx, op, event.WithHeader(
		"event", "ssh_upstream_host_key_verification_failed",
		"target_id", targetID,
		"host_key_fingerprint", fingerprint,
	)); err != nil {
		event.WriteError(ctx, op, berrors.Wrap(ctx, err, berrors.Op(op)))
	}
}

func (eventReporter) SessionRejected(ctx context.Context, targetID, reason string) {
	const op = "ssh.eventReporter.SessionRejected"
	if err := event.WriteObservation(ctx, op, event.WithHeader(
		"event", "ssh_session_rejected",
		"target_id", targetID,
		"reason", reason,
	)); err != nil {
		event.WriteError(ctx, op, berrors.Wrap(ctx, err, berrors.Op(op)))
	}
}
