// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package notify is a pure-Go library for sending approval notifications, such
// as access request events, to external receivers. The only notifier today is
// WebhookNotifier: a signed HTTPS POST with an SSRF-safe transport and bounded
// retries.
//
// Nothing in the controller or worker references this package yet, so it
// enables no capability and has no storage or API. Every failure path is closed:
// invalid configuration, a destination that is not permitted, an oversized body
// or an exhausted retry budget all return an error and never panic.
//
// The webhook signing secret is supplied by the caller as a []byte. It is never
// logged and never included in an error. When this library is wired, callers
// must source the secret from the credential/KMS machinery rather than from
// plain configuration. The destination URL may itself be a secret (chat
// webhook URLs are), so errors never contain it either.
package notify
