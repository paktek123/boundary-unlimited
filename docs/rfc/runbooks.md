# RFC: Runbooks (parameterised, reviewable scripts run through targets)

Status: Draft (security decisions recorded)  
Tracking: epic #89, issue #192  
Implemented by: nothing yet; this RFC is docs only. No runbook resource, API,
CLI or option exists or may be accepted until the enforcing code exists (see
Rollout slicing).

## Summary

A runbook is a reviewed, versioned script with declared parameters. Administrators
publish runbooks from a Git repository; users run them against a target without
free-form shell access. A run always goes through an existing target session,
so session recording, data masking and guardrails apply unchanged. This RFC is
an independent design; it describes user-visible behaviour only and does not
copy any other product's format or text.

## Goals

* Give users a safe alternative to free-form shell: they supply validated
  parameter values, never script text.
* Make what ran reproducible and auditable (pinned commit, script hash).
* Allow a run to require approval, reusing the access request machinery
  (`docs/rfc/access-requests.md`).
* Fail closed on any validation, fetch, hash or policy error.

## Non-goals

* A web UI in v1.
* AI authoring of runbooks.
* Interpreters that cannot take bound input (see Open security questions).
* Being a sandbox against a malicious script body (see Threat table).

## Runbook definition

A runbook is a versioned file in the Git source with:

* `name`, `description`.
* `target selector`: which targets it may be run against (target ids and/or
  scope; empty means none, never all; an explicit `all-targets` flag is
  required, as for masking and guardrails).
* `interpreter`: one that supports binding of parameters (first release:
  POSIX shell via environment variables/argv; SQL clients with bound
  parameters are a later slice).
* `parameters`, an ordered list. Each has:
  * `name` (validated, see below), `type` (`string`, `int`, `enum`, `bool`),
  * a mandatory RE2 `regex` (string) or `allowed_values` (enum), numeric
    bounds for `int`,
  * `max_length` (hard global cap, default 4 KiB, compile-time maximum),
  * `required`, optional `default` (which must itself pass validation).
* `script`: the body. It refers to parameters only by variable name
  (for example `"$RB_HOST"`), never by textual placeholder substitution.

Unknown fields, undeclared parameters, duplicate or missing required
parameters, and any validation failure reject the run before anything is sent
to the target.

## Injection-safe rendering model

Parameters are never concatenated into shell text. Options compared:

| Option | Description | Assessment |
|---|---|---|
| A | Per-interpreter quoting with a strict character allowlist, substituted into script text | Simple for authors, but safety depends on per-shell quoting rules (sh, bash, PowerShell, SQL); one mistake is an injection |
| B | No text substitution: parameters delivered as environment variables, argv elements or bound query parameters; the script refers to them by variable name | Removes the injection class by construction; less convenient for plain text scripts |
| C | B by default, A only for interpreters that cannot bind, per-runbook opt-in | The opt-in is controlled by the runbook author, the party being constrained |

**Decision (see Security decisions): B only.** Text substitution is not
permitted at all in the first release. Interpreters that cannot take bound
input are not supported until a later, separately reviewed decision.

Delivery rules:

* Environment variable names get a fixed, namespaced prefix and must match
  `^[A-Z][A-Z0-9_]*$`. Names that collide with dangerous variables (`PATH`,
  `LD_PRELOAD`, `LD_LIBRARY_PATH`, `IFS`, `BASH_ENV`, `ENV`, `SHELLOPTS`,
  `PS4`, `PYTHONPATH`, and similar) are rejected at definition time.
* Values containing NUL or control characters are rejected.
* argv and bound-query delivery use the interpreter's native binding only.

## Source of runbooks

* Git repository, referenced by a pinned **full 40-hex commit SHA**. Branches,
  tags, short SHAs and any floating ref are rejected.
* The fetch is performed by the controller side only, over verified TLS or SSH
  with host key or CA verification and no trust-on-first-use.
* Limits: maximum total size, maximum file count, overall timeout. No
  submodules, no symlinks, no hooks, no clone-time scripts; nothing from the
  repository other than the declared runbook file is ever executed.
* Per run, record the commit SHA and the SHA-256 of the exact script bytes;
  re-verify the hash immediately before execution (TOCTOU). A mismatch is
  refused.
* Signature verification of commits is a possible future option, not in v1.

## Execution

* A run executes only through an existing target session (for example an SSH
  target). There is no new execution path and no new credential handling, so
  recording, masking and guardrails apply unchanged.
* A run may require an access request and approval. The approval is bound to
  the commit SHA, script hash, a canonical hash of the parameter values,
  requester, target and session; it is single use, its TTL is capped by the
  access-request maximum, and the requester cannot self-approve.
* Authorization uses dedicated actions `runbooks:create|read|update|delete|list|execute`
  at the owning scope. `*` grants must not silently cover them for roles that
  exist at upgrade. Child scopes may only add runbooks, never override a
  parent's.

## Audit

Events: run requested, started, finished (with exit status), refused. Fields:
runbook id, commit SHA, script hash, parameter **names only**, principal id,
target id, session id, outcome, time.

Forbidden in events, errors, logs, metric labels and panics: parameter values
and any hash of an individual value (low-entropy values are recoverable from a
hash). The canonical parameter hash used for approval binding lives only in
the approval record. Panics are recovered without printing parameter values.

## Threat table

| Threat | Resisted? |
|---|---|
| Parameter value injected into script structure | Resisted (binding only, validation, golden tests) |
| Floating ref or force-push swapping reviewed content | Resisted (pinned SHA, hash check before execution) |
| Parameter values leaking through audit | Resisted (names only) |
| Runbook execution bypassing recording, masking or guardrails | Resisted (only via existing target session) |
| Non-conforming input reaching the executor | Resisted (fail closed validation) |
| Approval replay or reuse for another run | Resisted (binding, single use, TTL) |
| Script body that itself evals or expands a variable unsafely (`eval "$P"`, `sh -c "$P"`, string-built SQL) | **Not resisted**; static lint is a tripwire only |
| Compromised repository admin landing a new reviewed-looking commit | **Not resisted** |
| Compromised approver | **Not resisted** |
| Secrets inside a script body | **Not resisted** (masking is best effort) |

## Security decisions

Recorded from the `Security decision (security reviewer)` comment on epic #89.

1. Option C tightened: parameters are never substituted into script text;
   delivery is by binding only (environment variables, argv, bound query
   parameters). Option A and a per-runbook opt-in to it are rejected for v1.
2. Definition format declares each parameter with type, mandatory RE2 regex or
   enum list, and max length; any validation failure rejects the run.
3. Static lint at definition time rejects (or requires an explicit, documented
   lint-pass marker recorded in audit) script bodies with known unsafe
   re-evaluation patterns (`eval`, `sh -c "$..."`, unquoted parameter
   expansion). The documentation must state that lint is a tripwire, not a
   guarantee.
4. Git source: pinned full SHA, verified transport, size and file-count
   limits, hash recorded and re-verified before execution.
5. Approvals bound as above; the approval-binding parameter hash is not in
   audit events.
6. Audit carries names only, never values or per-value hashes.
7. Execution only via an existing target session; dedicated `runbooks:*`
   actions that wildcard grants do not silently cover.
8. Enforcement-first: nothing may accept runbooks until the renderer,
   validator and executor exist and are tested in the same release.
9. Recover from panics without printing parameter values.

Testable acceptance criteria: a value with shell metacharacters, quotes,
newlines, `$()`, backticks, `;`, SQL fragments or NUL is delivered only as an
opaque bound value and the script argv/structure is byte-identical to a run
with a benign value (golden test); values failing type, regex, enum or length
are rejected before any bytes reach the target; reserved variable names are
rejected; a branch, tag or short SHA is rejected; a script-hash mismatch is
refused; canary values never appear in events, errors or logs; an approval
cannot be reused for another run, twice, or after TTL; self-approval is
rejected; existing wildcard roles do not gain `runbooks:*`.

## Open security questions

For the security reviewer; the formal decision on #89 already covers the main
design, these remain:

1. Future support for interpreters without binding (for example PowerShell
   scripts): is any safe design acceptable, or should they stay unsupported?
2. Commit signature verification: required, optional, or out of scope, and
   which trust roots.
3. Lint strictness: reject-only, or allow the documented lint-pass marker, and
   who may set it.
4. Whether bound SQL delivery needs its own review before the SQL slice.

## Rollout slicing

Each slice follows the enforcement-first rule: nothing accepts runbooks before
the code that validates and executes them exists.

1. This RFC (docs only).
2. Pure-Go renderer and validator: definition parsing, parameter validation,
   binding delivery, lint, with golden and canary tests. Not wired.
3. Git source fetcher with pinned SHA and hash recording, using fakes. Not
   wired.
4. Storage, API and CLI (needs protobuf tooling). The API must reject creation
   with a clear "not yet supported" error until slice 5 has merged.
5. Execution through a target session, audit events, approval binding and
   documentation; only here may runbooks be enabled.
