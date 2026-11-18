# Runbooks (status and operator notes)

Tracking: epic #89, issues #260 and #279. Design: [docs/rfc/runbooks.md](rfc/runbooks.md).

> **Status: not usable yet.** There is no runbook API, CLI or worker execution.
> The `runbooks` service is not registered in the controller, so no endpoint
> accepts a runbook definition, and running a runbook always returns "not yet
> supported". The pieces below are merged as libraries and database schema
> only. This page is the API documentation stub; it will describe the real API
> when the service is registered (issue #279).

## What is merged (not registered)

| Area | Location |
|---|---|
| Definition model, strict validation and lint (full 40-hex commit only, reserved names) | `internal/runbook` (`definition.go`, `validate.go`, `lint.go`, `stored_validate.go`) |
| Binding-only renderer (parameters delivered as environment values, namespaced variables) | `internal/runbook/render.go` |
| Pinned source fetching by commit and script hash | `internal/runbook/source` |
| Approval binding to the exact reviewed script | `internal/runbook/approval` |
| Run orchestration (verifies the pinned script, parameters and approval before any Executor call); no Executor exists and nothing imports it | `internal/runbook/run` |
| Oplog-backed repository over migration 115 (no script body is stored; only commit, path and SHA-256) | `internal/runbook/db` |
| Definition service (create, get, list, update, delete) with audit events | `internal/daemon/controller/handlers/runbooks` |
| `runbooks:*` grants | `internal/perms` |

## Rules the feature keeps

* **Explicit grants only.** A wildcard grant (`type=*` or a wildcard action)
  never covers runbooks; a user needs an explicit `runbooks` grant for every
  action.
* **Users supply values, never script text.** Parameters are validated and
  passed as data, not interpolated into a shell command line.
* **Pinned and reproducible.** A definition points at a full commit and the
  SHA-256 of the exact script bytes; any mismatch fails closed.
* **No script body in events or errors.** Audit events carry identifiers only.
* **Execution stays disabled** until the worker side exists and goes through a
  normal target session, so recording, masking and guardrails apply.

## Not yet available

Proto and HTTP/gRPC API, registration in the controller, the `boundary
runbooks` CLI, worker execution and approval-gated runs.
