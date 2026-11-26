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
| gRPC adapter for the generated `AccessRequestServiceServer` (requester from the authenticated actor, visibility limited to requester or scope approver, version required for decisions, revoke refused); **not registered** in the controller | `internal/daemon/controller/handlers/accessrequests` |
| `access-request` resource type and its explicit-only grants (`type=access-request;actions=create,list,read,cancel,approve,deny,revoke`); neither `type=*` nor `actions=*` ever covers it | `internal/types/resource`, `internal/perms` |
| Go SDK client for the access-request API (create, read, list, approve, deny, cancel, revoke); the controller does not serve the API yet, so every call fails | `api/accessrequests` |
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

## CLI and Go SDK (not usable yet)

The `boundary access-requests` commands (`create`, `read`, `list`, `approve`,
`deny`, `cancel`, `revoke`) and the Go SDK package `api/accessrequests` exist,
but the controller does not register the access-request API (#322), so they do
not work against any controller yet. Against a controller built from main,
`GET /v1/access-requests` fails with a server error that wraps "not found", and
every command reports that error. The CLI makes no authorization decision: the
controller will enforce explicit `access-request` grants, refuse self-approval
and hide other users' requests once the API is registered.

* `create` takes `-scope-id`, `-grant` (repeatable), `-duration-seconds` (an
  integer or a duration such as `1h`) and `-justification`. It has no name or
  description. Its generated `-h` usage example still mentions name and
  description; ignore it.
* `approve`, `deny`, `cancel` and `revoke` take `-id` and an optional
  `-version`; without it the command reads the request first (check-and-set).
  `revoke` may be refused by the server until it is supported.

## Not yet available

The adapter relies on an `ActorResolver` that the controller must implement
(authentication, and the approver and grant lookup per scope); that, with
registration of the API in the controller, is the key remaining work. Also
missing: the HTTP gateway, the CLI (`boundary access-requests`), revoke,
request creation through any endpoint, controller wiring of the notifier, and
any UI.
