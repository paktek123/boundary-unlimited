// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package runbook holds the definition model and parameter validator for
// runbooks (see docs/rfc/runbooks.md). Compile validates a Definition and
// (*Compiled).Validate checks run-time parameter values against it. Both fail
// closed. Parameter values are never substituted into script text and never
// appear in errors, panics or formatted results; only parameter names do.
// The package is a pure library; nothing references it, so it enables nothing
// by itself.
package runbook

// Lint is a tripwire, not a guarantee: it catches common unsafe re-evaluation
// patterns in script bodies but can be defeated. Binding-only delivery of
// values remains the actual protection.
