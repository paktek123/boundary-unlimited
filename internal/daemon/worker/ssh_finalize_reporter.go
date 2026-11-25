// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"

	sshproxy "github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
)

// sshFinalizeReporter is the production sshproxy.FinalizeReporter. It publishes
// one worker system event per finalisation so a failed finalisation is never
// silent. The event carries only the session id, the upload status and the
// attempt count; the error text is never included because it may contain
// storage paths or bucket details.
type sshFinalizeReporter struct{ write sysEventWriter }

var _ sshproxy.FinalizeReporter = sshFinalizeReporter{}

// RecordingFinalized implements sshproxy.FinalizeReporter. It never blocks and
// never fails the session.
func (r sshFinalizeReporter) RecordingFinalized(ctx context.Context, sessionID string, res upload.Result, err error) {
	if r.write == nil {
		return
	}
	msg := "ssh recording finalized"
	failed := err != nil || res.Err != nil
	if failed {
		msg = "ssh recording finalization failed"
	}
	r.write(ctx, "worker.sshFinalizeReporter", msg,
		"session_id", sessionID,
		"status", int(res.Status),
		"attempts", res.Attempts,
		"failed", failed,
	)
}
