// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package policyhook is a client for the external authorizer described in
// docs/rfc/external-authorizer.md. It is additive only (it can deny what the
// built-in grants allowed, never the reverse), fails closed on every error
// path, never caches ALLOW and audits every decision.
//
// This package is NOT WIRED: nothing outside tests imports it, no controller
// configuration or API field selects an authorizer, and AuthorizeSession does
// not call it. The caller must supply an *http.Client whose Transport uses the
// guarded dialer (internal/notify/dialer.go or the shared package that the
// SIEM sinks decision #54 extracts); that extraction must land before wiring.
package policyhook
