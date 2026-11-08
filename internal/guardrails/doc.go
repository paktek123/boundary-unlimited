// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package guardrails holds the rule model and compiler for command guardrails
// (see docs/rfc/guardrails.md). Compile validates a rule set and selects the
// rules that apply to one session. It fails closed: any invalid rule fails the
// whole set. The package is a pure library; nothing references it, so it
// enables nothing by itself.
package guardrails
