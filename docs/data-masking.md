# Data masking for proxied sessions (status and operator notes)

Tracking: epic #87. Design: [docs/rfc/data-masking.md](rfc/data-masking.md).

> **Status: not configurable yet.** Masking is implemented as a library and as
> an option of the worker's `ssh` proxy handler, which takes its rules from
> the controller-authorized session input. No API, CLI or controller setting
> can define masking rules yet, so no running deployment masks anything. This
> page will be updated when rules can be configured.

## What is merged

| Area | Location |
|---|---|
| Streaming redactor (bounded buffers) | `internal/masking` (`redactor.go`) |
| Built-in detectors, rule compilation, effective-policy merge (parent rules cannot be disabled by a child) | `internal/masking` (`detectors.go`, `compile.go`, `policy.go`, `rules.go`) |
| Counts-only audit events | `internal/masking` (`audit.go`), worker emitter in `internal/daemon/worker/ssh_wiring.go` |
| `ssh` handler option taking rules from the authorized session input, never from the client | `internal/daemon/worker/proxy/ssh/maskingwire.go` |

## Rules the feature keeps

* **Rules never come from the client.** Only the authorized session input can
  carry them.
* **Mandatory detectors on recorded sessions.** When a session is recorded, the
  built-in detectors always apply and cannot be switched off by a child rule.
* **Fail closed.** An invalid rule or policy is an error, not "no masking".
* **Counts only.** Audit events carry counts, rule ids, window times and the
  principal id; matched text is never logged or emitted.
* **Masking is not a security boundary against a determined user.** Pattern
  detection can miss data that is encoded, split or transformed; treat it as a
  mitigation and combine it with least-privilege grants and recording.

## Not yet available

Rule definition through the API/CLI, scope-level policy inheritance in the
controller, and masking for protocols other than `ssh`.
