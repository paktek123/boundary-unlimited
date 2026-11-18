# Guardrails for proxied sessions (status and operator notes)

Tracking: epic #88. Design: [docs/rfc/guardrails.md](rfc/guardrails.md).

> **Status: not configurable yet.** Guardrails are implemented as a library and
> as an option of the worker's `ssh` proxy handler, which takes its rules from
> the controller-authorized session input. No API, CLI or controller setting
> can define guardrail rules yet, and the worker does not select the `ssh`
> handler for any session, so no running deployment blocks or reviews anything.
> This page will be updated when rules can be configured.

## What is merged

| Area | Location |
|---|---|
| Rule model and compiler (a rule set either compiles completely or fails) | `internal/guardrails` (`rules.go`, `compile.go`) |
| Command normaliser, evaluator and block counter | `internal/guardrails` (`normalize.go`, `evaluate.go`, `counter.go`) |
| Counts-only audit events | `internal/guardrails` (`audit.go`), worker emitter in `internal/daemon/worker/ssh_wiring.go` |
| `ssh` handler option taking rules from the authorized session input, never from the client | `internal/daemon/worker/proxy/ssh/guardrailswire.go`, applied in `register.go` |

A rule's action is `deny` or `require_review`; there is no `allow` action.

## Rules the feature keeps

* **Rules never come from the client.** Only the authorized session input can
  carry them.
* **Fail closed.** The handler refuses a session that guardrails apply to, and
  relays nothing, when the rules do not compile, there are no rules, the
  principal id is missing, or no audit emitter is installed.
* **Counts only.** Audit events carry counts, rule ids, the rule set hash, the
  action and decision, and the principal id; command text and rule patterns are
  never logged or emitted, and errors do not carry them either.
* **Guardrails sit above recording.** A blocked command reaches neither the
  recording nor the target.
* **Guardrails are a mitigation, not a boundary against a determined user.**
  Command matching can miss commands that are encoded, split or run through
  another program; combine it with least-privilege grants and session recording.

## Not yet available

Rule definition through the API/CLI, scope-level rule inheritance in the
controller, and guardrails for protocols other than `ssh`.
