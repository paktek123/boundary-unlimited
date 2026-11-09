// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package run orchestrates one runbook execution: fetch the pinned script,
// re-verify its hash, validate the parameters, check the approval binding and
// the target selector, render the invocation, emit the start audit event and
// only then call an Executor. Every check happens before the first byte
// reaches the Executor and any failure fails closed.
//
// This package is NOT WIRED: nothing outside tests imports it, no Executor
// implementation exists and no API, CLI or worker path uses it.
package run
