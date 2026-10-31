# RFC: Data masking for proxied sessions

Status: Draft  
Tracking: epic #87, issue #148  
Implemented by: #147 (redactor library, standalone); rule storage, API and
wiring slices are not filed yet

## Summary

Redact sensitive values (card numbers, access keys, tokens, private keys,
user-defined patterns) from session output before it reaches the client and
before it is written to a session recording. Masking is a worker-side output
filter driven by rules. This RFC is an independent design; it does not copy
any other product's documentation.

## Goals

* Stop sensitive data in server-to-client streams from reaching the user's
  terminal or client application, and from being persisted in recordings.
* Streaming operation: no buffering of whole sessions, bounded memory, matches
  found even when split across reads.
* Fail closed: if masking cannot run, output is dropped, not passed through.
* Rules are scoped (target, role, scope) and auditable without ever logging
  the values that matched.

## Non-goals

* ML or heuristic classification of data.
* Input-side guardrails (what a user may type or run); these belong to #88.
* Masking of data at rest in the target system.
* Protection against a user who can reshape output (for example `base64`,
  `rev`, character splitting). Masking is a DLP safety net, not a security
  boundary against a determined insider. Docs must say so.

## Rule model

A rule has:

* `id`, `name`, `description`, `scope_id` (owning scope).
* `detector`: either a built-in type (`credit_card` with Luhn check, `email`,
  `aws_access_key`, `jwt`, `private_key`) or a `regex` (RE2 syntax only, so
  matching is linear time; a compile-time length limit applies).
* `replacement`: default `[REDACTED:<detector>]`; must not contain the matched
  text (no back-references to the match in the first iteration).
* `applies_to`: a set of target ids, and/or role/principal selectors, and/or
  scope ids (including children). Empty selectors mean "none", never "all";
  an explicit `all-targets` flag is required to match everything.
* `enabled`.

Evaluation: all enabled rules applicable to a session are compiled into one
`Redactor` at session start. The rule set is snapshotted per session; changing
a rule affects new sessions only (documented).

Precedence: masking only ever adds redactions. There is no rule that unmasks.
Overlapping matches are merged to the widest span.

## Enforcement points

1. **Worker output filter.** The worker wraps the upstream-to-client data path
   (SSH channel data, and later other protocols) with the streaming redactor
   from #147. Applied before bytes are written to the client connection.
2. **Recordings.** The same redactor is applied before bytes enter BSR
   channel chunks, so recordings never hold the raw value. A single
   redaction pass feeds both the client and the recorder, so they cannot
   disagree.
3. Plain TCP targets: masking is only offered where the worker already
   terminates and understands the protocol. Raw TCP streams are masked as byte
   streams only if a later decision enables it, since binary protocols can be
   corrupted by replacement of different length.

The terminal-input direction is not masked; it can contain secrets typed by
the user (see the recording RFC).

## Failure modes

| Failure | Behaviour |
| --- | --- |
| Rule fails to compile at session start | Session creation fails; no unmasked session. |
| Detector error or panic mid-session | Output stops, session terminated, event emitted. Held bytes are discarded, not flushed. |
| Lookbehind buffer limit exceeded | Fail closed as above (never emit unscanned bytes). |
| Worker without masking support | Session creation fails for targets with applicable rules. |
| Rules cannot be fetched | Session creation fails. |

At session end the redactor is flushed after a final scan; held bytes are
emitted only if the scan succeeded.

## Performance limits

* Memory per session bounded by the maximum match length plus a fixed
  lookbehind (configurable, with a hard cap).
* Target throughput measured by the 1 MiB benchmark in #147; the RFC sets no
  absolute number until measured. Regex rules are RE2 only and limited in
  number per session.
* Sessions with many rules or very large lookbehind may be rejected at
  creation rather than degrade silently.

## Audit

Events when masking fires: session id, rule id, detector type, count of
redactions, time window. Counts only. Matched values, surrounding text and
offsets that would allow reconstruction are never logged, never put in error
messages and never in metrics labels. Rule create/update/delete are audited
like other resources. A summary count is also stored on the session recording
record (follow-up).

## Rollout slicing

Mapped to children of #87:

1. #147 redactor library (standalone, not wired).
2. #148 this RFC.
3. Rule resource: protobuf, DB migration, domain, API, CLI. Blocked on proto
   tooling; must not be exposed until the filter (4) enforces it
   (enforcement-first).
4. Worker wiring for SSH: apply the redactor in the client path and the
   recording path, with fail-closed behaviour above.
5. Docs and CHANGELOG.

Rule fields accepted by the API only in the same release as the wiring.

## Open security questions

For the security reviewer; none are decided here.

* Who may create, change or disable masking rules, and which new grant actions
  are required? May a target-level admin disable a rule that a parent scope
  imposed?
* May the audit event include which principal triggered a redaction, and may
  it include the rule's replacement text? What is the minimum safe event
  content?
* Should the built-in detector set be mandatory (cannot be disabled) for
  recording-enabled targets?
* Is a lookbehind buffer holding unmasked bytes in worker memory acceptable,
  and should it be zeroed after use?
* Retention of already-recorded sessions made before a rule existed.
