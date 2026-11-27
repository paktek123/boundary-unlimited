# Runbooks (status and operator notes)

Tracking: epic #89, issues #260 and #279. Design: [docs/rfc/runbooks.md](rfc/runbooks.md).

> **Status: read and delete only.** The controller serves `GetRunbook`,
> `ListRunbooks` and `DeleteRunbook` (gRPC and the HTTP gateway) once this is
> merged, each behind an explicit `runbooks` grant resolved through
> `auth.Verify`. `CreateRunbook` and `UpdateRunbook` are not served
> (`Unimplemented`), there is no CLI or worker execution, and running a
> runbook always returns "not yet supported". If the repository, audit emitter
> or caller resolver cannot be built at startup the API is not registered and a
> system event with a fixed reason is written. Design and tracking: issue #320.

## What is merged

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
| Caller resolver backed by `auth.Verify` (refuses anonymous and recovery-token callers; fixed error text) | `internal/daemon/controller/handlers/runbooks/verified_caller.go` |
| Go SDK client for reading and deleting runbooks | `api/runbooks` |

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

The gRPC adapter
(`internal/daemon/controller/handlers/runbooks/grpc.go`) implements get, list
and delete, which the controller registers (`runbook_wiring.go`), and pin-only
`CreateRunbook` and `UpdateRunbook`. The controller wrapper deliberately does
not serve create or update yet (they stay `Unimplemented` over the API). The
adapter never returns script bodies. Create and update accept only the pin
(`commit_sha`, a full 40 hex character commit, and `script_path`) plus
metadata and parameter definitions; the stored definition is `unverified` (no
`script_sha256`), changing the pin resets it to `unverified`, and
`Service.Run` always returns "not yet supported", so an unverified definition
can never be run. No production script fetcher exists (#279, #321). Still missing: the HTTP gateway, registration
in the controller (caller and grant resolution, DB repository), the
`boundary runbooks` CLI, worker execution and approval-gated runs.
