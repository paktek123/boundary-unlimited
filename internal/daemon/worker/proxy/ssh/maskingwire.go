// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/masking"
)

// DefaultMaskingAuditWindow is the aggregation window of masking audit events
// when the session input does not set one.
const DefaultMaskingAuditWindow = 10 * time.Second

// MaskingInput is the plain, decoded masking configuration of one session.
// Rules come from the authorized session input, never from the client.
type MaskingInput struct {
	// PrincipalID is the user the audit events are attributed to.
	PrincipalID string
	// Rules, ChildDisabled, IncludeEmail, AllowNoop, Session and Limits are
	// passed to masking.EffectivePolicy. RecordingEnabled there is taken from
	// the session configuration, so the mandatory built-in detectors always
	// apply on recorded sessions.
	Rules         []masking.PolicyRule
	ChildDisabled []string
	IncludeEmail  bool
	AllowNoop     bool
	Session       masking.SessionInfo
	Limits        masking.Limits
	// AuditWindow is the aggregation window; zero selects the default.
	AuditWindow time.Duration
}

var (
	maskEmitterMu sync.RWMutex
	maskEmitter   masking.Emitter
)

// InstallMaskingEmitter installs the counts-only masking audit emitter used by
// the registered ssh handler, bound to the worker event emitter at startup.
// Passing nil uninstalls it, after which masked sessions are refused.
func InstallMaskingEmitter(em masking.Emitter) {
	maskEmitterMu.Lock()
	defer maskEmitterMu.Unlock()
	if isNilValue(em) {
		em = nil
	}
	maskEmitter = em
}

func installedMaskingEmitter() masking.Emitter {
	maskEmitterMu.RLock()
	defer maskEmitterMu.RUnlock()
	return maskEmitter
}

// maskingOptions builds the handler options that enforce masking for cfg. It
// returns an error, and no options, when the effective policy does not compile
// or no audit emitter is installed. Errors never carry rule patterns or values.
func maskingOptions(ctx context.Context, cfg SessionConfig) ([]HandleOption, error) {
	if cfg.Masking == nil {
		return nil, nil
	}
	in := cfg.Masking
	em := installedMaskingEmitter()
	if em == nil {
		return nil, errNew(ctx, "ssh.maskingOptions", "no masking audit emitter installed")
	}
	pol, err := masking.EffectivePolicy(masking.PolicyInput{
		RecordingEnabled: cfg.RecordingEnabled,
		IncludeEmail:     in.IncludeEmail,
		AllowNoop:        in.AllowNoop,
		Rules:            in.Rules,
		ChildDisabled:    in.ChildDisabled,
		Session:          in.Session,
		Limits:           in.Limits,
	})
	if err != nil || pol == nil {
		return nil, errNew(ctx, "ssh.maskingOptions", "masking policy does not compile")
	}
	w := in.AuditWindow
	if w <= 0 {
		w = DefaultMaskingAuditWindow
	}
	return []HandleOption{
		WithMasking(pol),
		WithMaskingRequired(),
		WithMaskingAudit(em, in.PrincipalID, w),
	}, nil
}
