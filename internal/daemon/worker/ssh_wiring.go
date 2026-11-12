// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	sshproxy "github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/guardrails"
	"github.com/hashicorp/boundary/internal/masking"
)

const (
	// sshScratchDir is the sub-directory of recording_storage_path used for the
	// ssh recording scratch store, kept apart from the upstream storage files.
	sshScratchDir = "ssh-scratch"
	// defaultSSHScratchQuota bounds the bytes the ssh scratch store may hold.
	// Writes beyond it fail, which terminates the recorded session (fail closed).
	defaultSSHScratchQuota int64 = 10 << 30
)

// sysEventWriter matches event.WriteSysEvent and lets tests capture output.
type sysEventWriter func(ctx context.Context, op event.Op, msg string, args ...any)

// maskingSysEmitter publishes counts-only masking audit events as worker
// system events. It only forwards the fields of masking.Event.
type maskingSysEmitter struct{ write sysEventWriter }

// Emit implements masking.Emitter.
func (e maskingSysEmitter) Emit(ctx context.Context, ev masking.Event) error {
	if e.write == nil {
		return fmt.Errorf("worker: masking emitter has no writer")
	}
	e.write(ctx, "worker.maskingAudit", string(ev.Type),
		"session_id", ev.SessionId,
		"rule_id", ev.RuleId,
		"detector", ev.Detector,
		"count", ev.Count,
		"window_start", ev.WindowStart.UTC().Format(time.RFC3339),
		"window_end", ev.WindowEnd.UTC().Format(time.RFC3339),
		"principal_id", ev.PrincipalId,
	)
	return nil
}

// guardrailsSysEmitter publishes counts-only guardrails audit events as worker
// system events. It only forwards the fields of guardrails.Event.
type guardrailsSysEmitter struct{ write sysEventWriter }

// Emit implements guardrails.Emitter.
func (e guardrailsSysEmitter) Emit(ctx context.Context, ev guardrails.Event) error {
	if e.write == nil {
		return fmt.Errorf("worker: guardrails emitter has no writer")
	}
	e.write(ctx, "worker.guardrailsAudit", string(ev.Type),
		"session_id", ev.SessionId,
		"rule_id", ev.RuleId,
		"rule_set_hash", ev.RuleSetHash,
		"action", string(ev.Action),
		"decision", string(ev.Decision),
		"count", ev.Count,
		"principal_id", ev.PrincipalId,
		"timestamp", ev.Timestamp.UTC().Format(time.RFC3339),
	)
	return nil
}

// installSSHAuditEmitters installs the counts-only masking and guardrails
// emitters on the registered ssh handler. Installing them enables nothing by
// itself: masking and guardrails stay off unless a session configures them.
func installSSHAuditEmitters(write sysEventWriter) {
	sshproxy.InstallMaskingEmitter(maskingSysEmitter{write: write})
	sshproxy.InstallGuardrailsEmitter(guardrailsSysEmitter{write: write})
}

// newSSHScratch builds the ssh recording scratch store under the configured
// recording storage path. It returns nil, nil when no path is configured.
func newSSHScratch(recordingStoragePath string) (*scratch.Store, error) {
	if recordingStoragePath == "" {
		return nil, nil
	}
	return scratch.New(filepath.Join(recordingStoragePath, sshScratchDir), defaultSSHScratchQuota)
}

// recoverSSHScratch registers recordings left over from a previous process.
// It never deletes anything. A nil store is a no-op.
func recoverSSHScratch(ctx context.Context, s *scratch.Store, write sysEventWriter) error {
	if s == nil {
		return nil
	}
	orphans, err := sshproxy.RecoverScratch(ctx, s)
	if err != nil {
		return err
	}
	if len(orphans) > 0 && write != nil {
		write(ctx, "worker.recoverSSHScratch", "recovered ssh recording scratch",
			"orphans", len(orphans))
	}
	return nil
}
