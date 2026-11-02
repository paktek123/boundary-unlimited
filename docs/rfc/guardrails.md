# RFC: Guardrails for proxied sessions

Status: Draft  
Tracking: epic #88, issue #156  
Implemented by: nothing yet; this RFC only proposes the design and the slicing

## Summary

Guardrails are input-side rules evaluated by the worker on what a user sends
into a proxied session (for example an SSH exec request or a line typed in a
shell). A matching rule either **denies** the command or marks it as
**require-review**, meaning it may only run once an approval exists. This RFC
is an independent design; it does not copy any other product's documentation.

## Goals

* Stop clearly risky commands (for example destructive filesystem or database
  statements) from reaching the target, based on rules an administrator writes.
* Fail closed: any error while parsing input or evaluating rules blocks the
  command; it never allows it.
* Rules are scoped (target, role, principal, scope) and auditable without
  logging more command text than the security reviewer permits.
* Reuse the just-in-time access request machinery (#3) for require-review
  instead of inventing a second approval flow.

## Non-goals

* ML or heuristic risk scoring.
* Output-side filtering or masking; that is #87.
* Being a security boundary against a determined user who can obfuscate a
  command (shell expansion, encoding, scripts written to disk and run). Guardrails
  are a safety net against mistakes and casual misuse. Documentation must say so.
* Protocol-aware parsing of SQL or other protocols in the first iteration. That
  is a later target-type concern (see slicing).

## Rule model

A rule has:

* `id`, `name`, `description`, `scope_id` (owning scope).
* `match`: a pattern against the command text. First iteration: exact
  prefix/word match and RE2 regular expressions only (linear time). A
  compile-time pattern length limit and a per-session rule count limit apply.
  Later: protocol-aware matchers (SQL statement kind, table names).
* `action`: `deny` or `require_review`. There is no `allow` action; guardrails
  only ever restrict. If `deny` and `require_review` rules both match, `deny` wins.
* `applies_to`: target ids, and/or role/principal selectors, and/or scope ids
  (including children). Empty selectors mean "none", never "all"; an explicit
  `all-targets` flag is required to match everything (same rule as data masking).
* `message`: optional literal text shown to the user when blocked (no
  placeholders, so it can never echo the command).
* `enabled`.

The rule set is compiled and snapshotted when the session is authorized.
Changing a rule affects new sessions only (documented), the same as masking.

## Enforcement points

1. **Worker input path.** For SSH, the worker inspects `exec` requests, and
   (best effort) lines entered in an interactive shell channel, before they are
   forwarded to the upstream. Line reassembly from a raw keystroke stream is
   inherently lossy (editing keys, history, tab completion, paste); the first
   iteration therefore enforces reliably on `exec` requests and on
   non-interactive input, and documents that interactive shell enforcement is
   best effort until a design for it is accepted (open question 4).
2. **Session creation.** A target with applicable guardrail rules whose worker
   does not support guardrails must fail to authorize a session (no silent
   downgrade), the same as masking.
3. **Control plane.** Rules are stored and managed by the controller; the
   worker receives the compiled-ready rule set with the session authorization.

Nothing may accept or store guardrail rules until the worker enforcement for
them has merged (enforcement-first). Groundwork slices are pure Go libraries
that nothing references.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| Rule fails to compile at session start | Session creation fails. |
| Worker without guardrail support | Session creation fails for targets with applicable rules. |
| Rules cannot be fetched | Session creation fails. |
| Input cannot be parsed or exceeds the maximum inspected length | Command blocked, event emitted. |
| Evaluator error or panic | Command blocked, event emitted. |
| `require_review` but approval service unreachable or approval malformed | Command blocked. |

A blocked command is not forwarded at all; the user receives the rule's
`message` or a generic one. Whether the session is also terminated after N
blocked commands is open question 6.

## Interaction with access requests (#3)

For `require_review`, the blocked command can be turned into an access request
bound to a hash of the command text and the session id, approved by someone
other than the requester under the approver rules from the access-request
security decision (dedicated approve action, self-approval rejected, bounded
TTL). Approval authorizes only that exact command once, within the TTL; any
change to the text needs a new approval. The first iteration ships `deny`
only; `require_review` is added after the access-request overlay and approval
enforcement exist.

## Audit

Events when a guardrail fires: session id, rule id, action, the decision, and a
count. The command text is **not** logged by default; a SHA-256 of it may be,
subject to open question 2. Rule create/update/delete are audited with rule ids
and field names, not matched text. Events contain no credentials and are
emitted before the decision is acted on.

## Performance limits

* Per-command evaluation is linear in the inspected length, bounded by a hard
  maximum command length (longer input is blocked).
* Maximum number of rules per session and pattern length are configurable with
  hard caps; sessions exceeding them are rejected at creation.

## Rollout slicing

All pure-Go, unwired slices first; each maps to a child of #88:

1. This RFC (#156).
2. Rule model and compiler: selectors, limits, fail-closed validation (mirrors
   `internal/masking` rules/compile).
3. Command evaluator: normalisation, bounded length, deny wins, errors block.
4. Audit event types (no command text).
5. Worker integration for SSH `exec` behind the existing session handler
   option pattern, enforcing before any API can store rules.
6. Rule storage, API, CLI (only after 5 has merged).
7. `require_review` via access requests (after #3 enforcement).
8. Protocol-aware matchers (SQL) as a later target-type concern.

## Open security questions

For the security reviewer; not decided here.

1. **Authorization of rule management.** Which action and scope may create,
   change, disable or delete guardrail rules? Can a rule administrator weaken
   rules for sessions they themselves run?
2. **What may be logged.** Is the command text, a hash, or only the rule id
   allowed in audit events? Commands often contain secrets.
3. **Bypass resistance.** How much shell obfuscation (quoting, variable and
   command substitution, encodings, here-docs, scripts) must be handled, and
   what must documentation promise?
4. **Interactive shells.** Is best-effort enforcement on interactive channels
   acceptable, or must targets with guardrails refuse interactive shells?
5. **Unicode and normalisation.** Required normalisation before matching, and
   the behaviour on invalid UTF-8 (proposal: block).
6. **Repeated blocks.** Should a session be terminated after repeated blocked
   commands?
7. **Review binding.** Confirm the proposed binding of an approval to the exact
   command hash, session and TTL.
