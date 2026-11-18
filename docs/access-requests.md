# Just-in-time access requests (status and operator notes)

Tracking: epic #3, issue #18. Design: [docs/rfc/access-requests.md](rfc/access-requests.md).

> **Status: not usable yet.** There is no API, CLI or SDK to create, approve or
> list access requests (issue #18), and requests cannot be created through any
> endpoint. The state machine, approval policy, repository, service, grant
> overlay and sweeper are merged as libraries. This page records what exists
> and the rules the feature keeps; it will be updated when the API lands.

## What is merged

| Area | Location |
|---|---|
| Request lifecycle and state machine (pending, approved, denied, cancelled, expired, revoked) | `internal/accessrequest` (`request.go`) |
| Approval policy (max TTL, self-approval refused) | `internal/accessrequest` (`approval.go`) |
| In-memory and database-backed repositories over the oplog (migrations 114 and 116); concurrent decisions end in exactly one terminal state | `internal/accessrequest` (`memrepo.go`, `dbrepo.go`) |
| Service composing policy, audit events and notifications | `internal/accessrequest` (`service.go`) |
| Grant overlay: approved, unexpired requests add exactly their approved grants for `authorize-session` | `internal/accessrequest/merge.go`, `internal/daemon/controller/handlers/targets/overlay_authorizer.go` |
| Sweeper that audits and then expires overdue requests | `internal/accessrequest` (`sweeper.go`) |
| Notification fan-out and `notifier` config (the stanza is still refused at load) | `internal/notify`, [docs/notifier.md](notifier.md) |

## Rules the feature keeps

* **Fail closed.** If the overlay source, clock or audit sink fails, the user
  keeps only their normal grants; an unauditable grant is never given.
* **Narrow grants.** Overlay grants are limited to the request's scope and
  wildcard grants are dropped. Approval is bound to the exact grants that were
  reviewed (grant hash).
* **No self-approval**, and terminal requests are frozen.
* **Audited.** Create, approve, deny, cancel, expire and every overlay grant
  emit identifier-only events; justifications and secrets are never included.
* Access ends at the approved `not_after` time even if nobody revokes it.

## Not yet available

API handler and CLI (`boundary access-requests`), request creation, controller
wiring of the notifier, and any UI.
