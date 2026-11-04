# RFC: Just-in-time access requests and approvals

Status: Draft (security decision recorded)  
Tracking: epic #3, issue #15  
Implemented by: groundwork libraries only (`internal/accessrequest`, the
`access_request` migration 114, `internal/notify`); no API, CLI or controller
wiring exists yet

## Summary

A user without standing access to a target can file an **access request** for
specific grants, for a bounded time, with a justification. A different
principal who is allowed to approve reviews it. While a request is approved and
unexpired, its grants are added to the requester's resolved grants for each
authorization decision. Nothing is written to roles, and expiry is enforced by
the clock on every decision. This RFC is an independent design; it does not
copy any other product's documentation.

## Goals

* Time-bounded, auditable elevation of access without standing privileges.
* Fail closed: any error in the request path contributes zero extra grants.
  Baseline (non-overlay) access is never reduced by a failure here.
* No fail-open window: expiry does not depend on a background job running.
* Least privilege: an approver cannot grant what they could not exercise.

## Non-goals

* Changing how roles and grants are stored or resolved.
* Multi-step approval chains, quorum approval, or delegated approval.
* Break-glass access that bypasses approval.
* Reviewing guardrail-blocked commands; that reuses this flow later (see
  `docs/rfc/guardrails.md`).

## Request model

A request (`accessrequest.Request`) has an id, requester id, scope id, the
requested grant strings, a justification (length-bounded), a duration, a state
and timestamps. States: `pending`, `approved`, `denied`, `cancelled`,
`expired`, `revoked`; the last four are terminal.

* Limits (all configurable, all with defaults): maximum duration (default
  8h; the security decision caps the default at 24h), maximum pending age,
  maximum justification length, maximum number of grants.
* The requested grants are **immutable** after creation. Any edit creates a
  new request that needs a new approval.
* The requester can cancel their own pending request. Nobody can cancel
  another user's request.

## Authorization: overlay evaluated at decision time

Chosen design (security decision on #15, option A): an **overlay** evaluated
at authorization time. Approved, unexpired requests contribute grants that are
merged into the requester's resolved grants (after `GrantsForUser` in
`internal/iam`), so existing scope and ACL logic is reused. Nothing is written
to `role_grant`, and there is no schema change to roles.

Rejected alternatives:

* B, temporary role grants removed by a sweeper: fail-open window if the
  sweeper stalls, needs a `role_grant` schema change, persists privileges.
* C, hybrid of B plus a read-time check: keeps B's standing mutation and adds
  complexity for no extra safety.

Rules for the overlay (`accessrequest.EffectiveGrants`):

1. A request contributes grants only inside `[approved_at, expires_at)`: a
   state of `approved`, `now >= approved_at` and `now < expires_at`.
   One tick after expiry the same call is denied, with no sweeper running. The
   sweeper (`accessrequest.Sweeper`) only tidies state and emits expiry events.
2. If the request store is unreachable, the clock check errors, or a record is
   malformed, the overlay contributes **zero** grants. Base grants are
   unaffected.
3. The overlay is computed per authorization call. It is never cached beyond
   the request, or any cache TTL is capped at a few seconds and never exceeds
   `expires_at`.
4. Overlay grants are scoped to the request's scope and are not recursive
   beyond what was approved. `*` or `id=*;actions=*` cannot be requested unless
   the approver holds exactly that.

## Approval

Approver model (3): the approver needs **both** a dedicated
`access-requests:approve` action on the requested scope **and** must already
hold every grant being requested (`accessrequest.ValidateApproval`).

* Self-approval is always rejected.
* Approval is bound to a hash of the requested grant strings
  (`accessrequest.GrantHash`, recorded by `RecordApproval`, re-checked by
  `VerifyApprovedGrants`), so a request widened after approval is invalid.
* Overlay grants can never exceed what the approver held at approval time. The
  approver's grants are re-checked at decision time, a reference to their grant
  snapshot is stored in the audit event, and approval is rejected if the
  approver's grants changed in the meantime.
* The approver cannot delegate approval through a role they control.
* A replayed old approval has no effect: it is bound to one request id, one
  grant hash and an expiry.

## Audit

Events are emitted before the grant takes effect and contain no credentials
(`accessrequest` event constructors reject credential-looking fields):

* create, approve, deny, cancel, expire;
* every authorization that was allowed **only** because of the overlay
  (`NewOverlayAuthorizedEvent`: request id and grant string).

## Notifications

Pending requests and decisions may be sent to external receivers by the
`internal/notify` library (signed webhook, fan-out). Notification events carry
only the request id, scope id, kind, timestamp and a fixed summary; never the
justification. Notification failure never changes the request outcome.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| Request store unreachable during authorization | Overlay adds zero grants; baseline access unchanged. |
| Clock error or malformed record | That request contributes nothing. |
| Approver lost a required grant since review | Approval rejected. |
| Request edited after approval | Approval invalid; a new request is needed. |
| Sweeper stalled | No effect on authorization; expiry is checked per decision. |
| Audit emit fails on a state change | The change is not applied. |

## Threats

Resisted: stale grants after expiry, sweeper stall, self-approval, approver
escalation, replay of an old approval, and a request widened after approval.

Not resisted: a compromised approver who legitimately holds the grants
(mitigated only by audit and short TTLs). Clock skew between controllers is
bounded by the maximum TTL and NTP; it is not eliminated.

## Rollout slicing

Enforcement-first: no API or CLI may accept requests until the overlay
enforcement and its tests are merged. Nothing may accept an option that is not
enforced.

1. This RFC (#15).
2. Lifecycle state machine (#144), repository interface, fake and sweeper
   logic (#145): pure Go, merged.
3. Overlay evaluator (#146), approval policy checks (#153), audit events
   (#154): pure Go, merged.
4. `access_request` migration (#174): inert schema, merged.
5. Notification library (#175, #183): pure Go, not wired.
6. Overlay wiring into authorization in `internal/iam`/`internal/auth`
   (enforcement) before anything below.
7. Controller repository and API/CLI to create, list, approve, deny and cancel
   (#16, #18 and following), only after 6 has merged.

## Open security questions

For the security reviewer; not decided here.

1. **Clock skew tolerance.** Is a fixed tolerance acceptable, or must expiry
   be evaluated with the stricter of controller and database time?
2. **Overlay cache.** Is any cache acceptable, or must the overlay be computed
   without a cache for the first release?
3. **Maximum TTL ceiling.** Is a hard ceiling above 24h ever acceptable for
   specific scopes?
