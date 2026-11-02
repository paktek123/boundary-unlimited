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

## Decisions

Recorded from the binding security decision on epic #87
(https://github.com/paktek123/boundary-unlimited/issues/87#issuecomment-6554773994).
These replace the earlier open security questions.

1. **Rule administration.** Dedicated actions
   `masking-rules:create|read|update|delete|list`, evaluated at the owning
   scope. There is no generic `*` shortcut: a `*` grant on a scope covers them
   only if it names the type explicitly, and the grant parser must not silently
   expand wildcards to the new resource type for existing roles at upgrade. A
   rule owned by a parent scope can be neither disabled, deleted, narrowed nor
   weakened from a child scope. Child scopes may only add rules. Disabling or
   weakening a rule requires the action at the owning scope. Rules never
   unmask ("masking only adds").
2. **Audit event content.** Allowed: session id, rule id, detector type,
   redaction count, time window, and principal id (the session already
   identifies the principal). Forbidden everywhere (events, errors, logs,
   metric labels, panics): matched values, surrounding text, byte offsets,
   per-occurrence match lengths, and replacement text. Replacement text is rule
   configuration readable by `masking-rules:read` holders and must not be echoed
   in events. Events carry counts per time window only (no per-match events) and
   are emitted via the existing events package.
3. **Mandatory built-ins.** On any target with `enable_session_recording=true`
   the built-in detector set (credit_card, aws_access_key, jwt, private_key;
   email may be configurable as it is low sensitivity) is always applied and
   cannot be disabled by any scope. Disabling requires removing recording from
   the target. Fail closed if the built-in set cannot be loaded.
4. **Lookbehind buffer.** Acceptable under these conditions: a hard cap on size
   (configurable, with a compile-time maximum); memory kept only in the
   session's redactor; zeroed on Close, flush, error and session termination
   (best effort in Go, by explicit overwrite of the backing array, documented as
   best effort); never written to disk; swap-eligible memory is a documented
   residual risk; never included in errors or panics (recover without printing
   buffer state).
5. **Pre-existing recordings.** No retroactive rewriting, because it would
   mutate evidence. Rule changes apply to new sessions only. The session
   recording record states whether masking was active and the rule-set
   version/hash, so reviewers can tell unmasked historical recordings apart.
   Access to recordings made without masking stays governed by the recording
   read grants.

### Required safeguards

* Rule resource API fields are accepted only in the same release as the worker
  wiring (enforcement-first). Nothing may accept a rule field that is not
  enforced.
* Fail closed everywhere in the failure-mode table; no pass-through path; held
  bytes are discarded on error, never flushed.
* Rule compiler: empty selectors match nothing, `all-targets` must be explicit,
  RE2 only, pattern length and rule count limits, replacement must not
  reference the match.
* One rule snapshot per session, with its hash stored for the recording record.
* Grant parser tests proving the new action type is not matched unintentionally
  by pre-existing wildcard roles.
* Logging and event tests with canary values proving no matched value, offset
  or replacement appears in events, errors or logs.
* Buffer zeroing on every exit path, including panic and cancellation.

### Threats

Resisted:

* child-scope tampering with rules;
* secrets leaking via audit events, errors or metrics;
* unmasked data persisted in recordings (mandatory built-ins);
* flush of unscanned bytes on failure;
* ReDoS (RE2 only).

Not resisted (residual risks):

* a user who reshapes output (base64, `rev`, splitting values across
  commands); this is a non-goal and users must be told so;
* a compromised owning-scope administrator, who may change or disable the
  rules that scope owns;
* memory scraping of a compromised worker, and swap, because the lookbehind
  buffer holds unmasked bytes briefly;
* secrets in the input direction (typed by the user).

### Testable acceptance criteria for later slices

* A child-scope principal cannot disable, delete or weaken a parent-scope rule,
  and can add one.
* A recording-enabled target always runs the built-in detectors even with all
  custom rules disabled.
* A canary secret passed through the redactor never appears in any captured
  event, error string or log line.
* A detector panic or buffer overflow terminates the session with zero
  unscanned bytes emitted.
* After Close, the lookbehind buffer's backing array is all zero.
* The recording record exposes whether masking was active and the rule-set hash.
