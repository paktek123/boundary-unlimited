# RFC: Guardrails for proxied sessions

Status: Draft (security decisions recorded)  
Tracking: epic #88, issues #156, #180  
Implemented by: nothing user-visible yet; groundwork libraries only (see slicing)

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
   best effort until a design for it is accepted (security decision 4).
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
blocked commands is decided in security decision 6.

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
count. The command text is **never** logged and no hash of it is logged;
forbidden by security decision 2. Rule create/update/delete are audited with rule ids
and field names, not matched text. Events contain no credentials and are
emitted before the decision is acted on.

## Performance limits

* Per-command evaluation is linear in the inspected length, bounded by a hard
  maximum command length (longer input is blocked).
* Maximum number of rules per session and pattern length are configurable with
  hard caps; sessions exceeding them are rejected at creation.

## Rollout slicing

All pure-Go, unwired slices first; each maps to a child of #88:

1. This RFC (#156) and the folding of the security decisions into it (#180).
2. Rule model and compiler (child #172): selectors, limits, fail-closed validation (mirrors
   `internal/masking` rules/compile).
3. Command evaluator: normalisation, bounded length, deny wins, errors block (child #181).
4. Audit event types (counts only, no command text, no hash; child #182).
5. Worker integration for SSH `exec` (child #184) behind the existing session handler
   option pattern, enforcing before any API can store rules.
6. Rule storage, API, CLI (only after 5 has merged).
7. `require_review` via access requests (after #3 enforcement).
8. Protocol-aware matchers (SQL) as a later target-type concern.

## Guardrails are a policy tripwire, not a sandbox

Guardrails match the literal command text forwarded to the upstream. They are a
safety net against mistakes and casual misuse. They are not a security
boundary against a determined user.

Not promised: resistance to quoting, variable or command substitution,
encodings, here-docs, scripts or files the user uploads then executes,
aliases, or commands assembled in the remote environment. Interactive input is
not covered unless `allow_interactive` is set, and then only best effort.
Also not resisted: a compromised owning-scope administrator, a malicious
approver, and secrets in stored review text beyond masking coverage.

## Security decisions

Recorded from the binding `Security decision (security reviewer)` comment on
epic #88. These replace the former "Open security questions".

1. **Rule administration.** Dedicated actions
   `guardrail-rules:create|read|update|delete|list` at the owning scope. A `*`
   grant covers them only if the grant names the type explicitly; the grant
   parser must not expand wildcards to this type for roles that exist at
   upgrade. Child scopes may only ADD rules; they cannot disable, delete,
   narrow or weaken a parent-scope rule. A rule administrator cannot weaken
   rules that apply to their own sessions: changes that reduce enforcement
   (disable, delete, loosen a pattern, raise a limit) are rejected when the
   actor holds an active or authorizable session on a target the rule covers,
   and must be made by a principal with no session on those targets (separation
   of duties). Every change emits an audit event with before/after rule ids and
   version, not pattern text.
2. **Audit content.** Allowed: session id, rule id and rule-set version, action
   (block/review/allow), decision, count, principal id, timestamp. Forbidden in
   events, errors, logs, metric labels and panics: command text, command
   fragments, match offsets, and any hash of the command. There is no opt-in
   hash. Repeated identical blocks are counted, not logged individually beyond
   the allowed fields.
3. **Bypass resistance.** Matching is on the literal command string forwarded
   to the upstream (the SSH exec request payload), after normalisation (item 5).
   No shell parsing and no deobfuscation. A per-target `exec_only` option
   refuses shell and subsystem channels and allows exec only; it is documented
   as the strongest available mode. Default-deny rule sets (allow-lists) must
   be supported by the compiler so operators need not rely on deny-lists.
4. **Interactive shells.** Targets to which any guardrail rule applies REFUSE
   interactive shell, pty-shell and subsystem channels by default (fail
   closed). Operators may opt in per target with an explicit `allow_interactive`
   setting, which emits an audit event at session start stating that
   enforcement is best-effort. Opt-in requires `guardrail-rules:update` at the
   owning scope and is not available to the session user. Documentation must
   state that interactive input is not covered.
5. **Normalisation.** Match on the exact bytes received plus a normalised form;
   block if EITHER the raw or the normalised form matches a block rule (review
   rules likewise). Normalisation: reject invalid UTF-8; reject NUL and
   ASCII/C1 control characters other than the tab and newline handling defined
   in this RFC; reject bidi override and zero-width/format characters (Unicode
   Cf); apply NFKC to the matching copy (not NFC); case-fold only where the rule
   asks. There is a hard maximum command length (compile-time constant, default
   8 KiB); longer commands are blocked. Block means the exec request is rejected
   and the channel closed; nothing is forwarded.
6. **Repeated blocks.** The session is terminated after N blocked commands
   (default 5, configurable per scope, minimum 1, maximum 20, 0 not allowed),
   with an event. The counter is per session and not resettable by the client.
7. **Review binding.** An approval is bound to the SHA-256 of the exact raw
   command bytes, the session id, the requester principal id and the target id;
   it is single use and expires at the lesser of the configured review TTL and
   the access-request max TTL. The hash is stored only in the approval record
   (never in audit events or logs). The approver must be shown the command
   text, so the review request record holds the command; it must pass through
   the masking detectors (#87) before display and storage, be kept only until
   the decision plus a short retention window, and be readable only by holders
   of the review action. An approval is invalid if the command, session,
   requester or target differ in any byte. The requester cannot approve their
   own review; the approver must hold `guardrail-reviews:approve` at the target
   scope.

## Appendix A: required safeguards

* Enforcement-first: no rule storage, API, CLI or option may be accepted until
  worker enforcement for it exists in the same release; nothing may accept a
  setting that is not enforced.
* Fail closed on every error path: compile failure, rule fetch failure,
  evaluator panic (recovered without printing the command), worker without
  guardrail support, unknown rule field, oversize or malformed input.
* Compiler (#172): RE2 only; pattern length, rule count and total size limits;
  empty selectors match nothing; `all-targets` must be explicit; unknown actions
  rejected; deterministic rule-set version hash.
* Canary tests proving no command text, fragment, offset or command hash appears
  in events, errors, logs or metrics.
* Grant parser tests proving existing wildcard roles do not silently gain
  `guardrail-rules:*` or `guardrail-reviews:*`.
* Constant-time comparison for the approval binding.
* Interactive-channel refusal covered by a test on a guarded target.

## Appendix B: testable acceptance criteria

* A child-scope principal cannot disable, delete or weaken a parent rule, but
  can add one; a rule admin with a session on a covered target cannot loosen the
  covering rule.
* Invalid UTF-8, NUL, control, bidi and format characters and over-length
  commands are blocked; a fullwidth or compatibility-form variant of a blocked
  command is blocked.
* Block, review and error outcomes forward zero bytes upstream.
* A session is terminated on the Nth block, with an event containing only
  allowed fields.
* On a guarded target a shell or subsystem channel request is refused unless
  `allow_interactive` is set, and enabling it emits the best-effort event.
* An approval for command X cannot be used for command Y, another session,
  another requester, a second time, or after TTL; self-approval is rejected.
* Canary command text never appears in any captured event, error or log line.
