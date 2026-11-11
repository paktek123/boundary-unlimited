// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"sync"

	"github.com/hashicorp/boundary/internal/guardrails"
)

// GuardrailsInput is the plain, decoded guardrails configuration of one
// session. Rules come from the authorized session input, never from the
// client.
type GuardrailsInput struct {
	// PrincipalID is the user the audit events are attributed to. Required.
	PrincipalID string
	Rules       []guardrails.Rule
	Session     guardrails.SessionInfo
	Limits      guardrails.Limits
	// BlockLimit is the number of blocked commands after which the session is
	// terminated; zero selects guardrails.DefaultBlocksBeforeTerminate.
	BlockLimit int
	// AllowInteractive permits shell and subsystem requests, which guardrails
	// cannot inspect. The default (false) refuses them.
	AllowInteractive bool
}

var (
	grEmitterMu sync.RWMutex
	grEmitter   guardrails.Emitter
)

// InstallGuardrailsEmitter installs the counts-only guardrails audit emitter
// used by the registered ssh handler, bound to the worker event emitter at
// startup. Passing nil uninstalls it, after which sessions with guardrails
// are refused.
func InstallGuardrailsEmitter(em guardrails.Emitter) {
	grEmitterMu.Lock()
	defer grEmitterMu.Unlock()
	if isNilValue(em) {
		em = nil
	}
	grEmitter = em
}

func installedGuardrailsEmitter() guardrails.Emitter {
	grEmitterMu.RLock()
	defer grEmitterMu.RUnlock()
	return grEmitter
}

// guardrailOptions builds the handler options that enforce guardrails for cfg.
// It returns an error, and no options, when the rules do not compile, there is
// no principal or no audit emitter is installed. Errors never carry rule
// patterns or command text.
func guardrailOptions(ctx context.Context, cfg SessionConfig) ([]HandleOption, error) {
	const op = "ssh.guardrailOptions"
	in := cfg.Guardrails
	if in == nil {
		return nil, nil
	}
	if in.PrincipalID == "" {
		return nil, errNew(ctx, op, "missing principal id")
	}
	em := installedGuardrailsEmitter()
	if em == nil {
		return nil, errNew(ctx, op, "no guardrails audit emitter installed")
	}
	if len(in.Rules) == 0 {
		return nil, errNew(ctx, op, "guardrails apply but no rules were supplied")
	}
	compiled, err := guardrails.Compile(in.Rules, in.Session, in.Limits)
	if err != nil || compiled == nil {
		return nil, errNew(ctx, op, "guardrail rules do not compile")
	}
	gopts := []GuardrailOption{WithGuardrailPrincipalId(in.PrincipalID)}
	if in.BlockLimit != 0 {
		gopts = append(gopts, WithGuardrailBlockLimit(in.BlockLimit))
	}
	if in.AllowInteractive {
		gopts = append(gopts, WithGuardrailAllowInteractive())
	}
	return []HandleOption{WithGuardrails(compiled, em, gopts...)}, nil
}
