# RFC: External authorizer hook on session authorization

Status: Draft (security decision recorded as final)  
Tracking: epic #62, issues #63, #64  
Implemented by: nothing. This RFC is documentation only; no code, config key or
API field exists for it.

## Summary

Operators want policy-as-code (for example OPA, or any service that can answer
an HTTPS request) to be able to say "not this session, not now" in addition to
Boundary's role grants. The hook is called from `AuthorizeSession`
(`internal/daemon/controller/handlers/targets/target_service.go`) after the
built-in grant check has allowed the request. It is **additive only**: it can
deny what grants allowed; it can never grant what grants deny. This RFC is an
independent design and does not copy any other product's documentation.

## Goals

* Let an external service veto a session authorization using a small, typed,
  minimal input document.
* Fail closed on every error path, with no `fail_open` setting in v1.
* Audit every decision (allow, deny, error, timeout) without leaking secrets.

## Non-goals

* Granting access that grants deny.
* Embedding an OPA/Rego engine in the controller (the hook is a remote call).
* Obligations, response-side data, or any response field other than `allow`.
* Break-glass. Handle it through an existing out-of-band path, not this hook.

## Options considered

| Topic | Options | Decision |
| --- | --- | --- |
| Transport | OPA REST API vs. generic HTTPS webhook | One generic HTTPS JSON contract. An OPA deployment can expose it (for example through an OPA REST endpoint or a thin adapter) because the response is a single boolean. No OPA-specific code. |
| On error/timeout | (a) always deny; (b) deny by default with a `fail_open` flag; (c) fail open | **(a) always deny.** (b) lets a policy author weaken the control for themselves and is hard to audit; it may only be revisited as a separate, later, operator-only, global, time-boxed, loudly audited security decision. (c) is unsafe. |
| Caching | none; cache ALLOW and DENY; cache DENY only | **DENY only**, off by default (see below). Caching ALLOW would make revocations ineffective for the cache lifetime. |
| Order | authorizer first vs. grants first | **Grants first**, then the authorizer; the final result is the AND of both. |

## Request flow

1. `AuthorizeSession` performs the normal grant check. A deny stops here and the
   authorizer is **not** called.
2. If grants allow, the controller builds the input document, calls the
   authorizer once with a context-bounded timeout, and reads the response with a
   bounded reader.
3. Only a well-formed response with a boolean `allow: true` lets the request
   continue. Everything else is DENY.
4. A decision audit event is emitted for every outcome.
5. The API client always gets the generic `access denied` error. It never
   learns the policy internals or the authorizer URL.

## Input document

The document is typed and minimal. These are **all** the fields; adding a field
is a reviewed change to this RFC and to the code.

| Field | Content |
| --- | --- |
| `principal_id` | id of the authenticated user or token owner |
| `user_id`, `account_id` | ids only |
| `group_ids`, `role_ids` | ids only |
| `target_id`, `target_type` | the requested target |
| `scope_ids` | the target's project and ancestor org/global scope ids |
| `host_id` | the selected host, when known |
| `action` | the action being authorized (for example `authorize-session`) |
| `request_time` | RFC 3339 UTC |
| `source_ip` | the client's address as seen by the controller |

The document **must not** contain tokens, credentials, secrets, injected
credential material, session keys, or raw grant strings. Names and free-text
descriptions are not sent either, because they are user-controlled strings.

## Response

```json
{ "allow": true }
```

Only the boolean `allow` is read. Unknown fields are ignored but never acted on.
A missing field, a non-boolean value (including the string `"true"`), invalid
JSON, an empty body, a non-2xx status, or a body larger than 64 KiB is DENY.

## Failure modes

| Condition | Result | Audit reason code |
| --- | --- | --- |
| Authorizer returns `allow: true` after grants allowed | continue | `allow` |
| Authorizer returns `allow: false` | DENY | `deny` |
| Connection error, DNS failure, blocked destination, TLS failure, non-2xx | DENY | `error` |
| Timeout (default 2 s, hard cap 5 s, context-bounded) | DENY | `timeout` |
| Invalid JSON, empty body, oversized body, missing or non-boolean `allow` | DENY | `invalid_response` |
| Panic anywhere in the hook | DENY (recovered without printing input) | `error` |

The zero value of the decision type is DENY. Misconfiguration (unknown config
keys, non-https URL) is rejected when the configuration is loaded, not at
request time.

## Transport and credentials

* The URL must be `https`. TLS verification is always on, TLS 1.2 minimum,
  system roots plus an optional CA bundle, hostname verification enforced. There
  is no `skip_verify` or `insecure` option; unknown keys, including anything that
  looks like `fail_open` or `skip_verify`, are rejected.
* Destinations are checked at connect time (after resolution, resisting DNS
  rebinding) with the guarded dialer: loopback, private, link-local (including
  169.254.169.254), unspecified and multicast addresses are refused unless an
  explicit allowed CIDR exists. Reuse the dialer in `internal/notify/dialer.go`
  or the shared package extracted by the SIEM sinks decision (#54); do not copy it.
* Redirects are not followed.
* Authentication to the authorizer uses a secret referenced by environment
  variable or file, never inline in HCL. The secret is never logged, never
  echoed in errors or config render, and redacted in `String`/`GoString`.
* Timeouts, response size and request size are bounded.

## Caching

* ALLOW is **never** cached. This is deliberate: a cached ALLOW would let a stale
  decision outlive a changed principal, grant or target.
* DENY may be cached, only because it can only make the system stricter and it
  limits load on a failing service. The key is a hash of the full input
  document, the TTL is at most 5 seconds, the cache is size-bounded, and it is
  **off by default** in the first release.

## Audit

Every decision emits an event through the existing events package with: request
or session id, principal id, target id, authorizer/policy id, decision, reason
code (`allow`, `deny`, `error`, `timeout`, `invalid_response`) and latency.
Never the full input, the response body, or any secret value.

## Enforcement-first rollout

1. This RFC (#63): documentation only.
2. A pure Go library for the client, decision type, DENY-only cache and the
   failure table, tested with fakes and not wired.
3. #64: controller configuration **and** the `AuthorizeSession` integration in
   the same slice. No config key or API field that selects an authorizer may land
   before the code that enforces it exists in the same slice; an accepted but
   unenforced option is a security finding.

## Residual risks (must be documented to operators)

* A compromised or malicious policy service that answers ALLOW for everything is
  still bounded by the built-in grants, because the hook can only restrict.
* A compromised controller can skip the hook.
* A policy that is wrong but available is still enforced as written.
* An outage of the policy service blocks all sessions that reach the hook. This
  is the accepted availability cost of failing closed.

## Acceptance criteria for the implementing slices

1. Table test: error, timeout, 500, 403, malformed JSON, empty body, `allow`
   missing, `allow` as the string `"true"`, and an oversized body each yield DENY
   and an audit event with the right reason code.
2. A fake authorizer returning ALLOW for a request that grants deny still results
   in a denied session.
3. ALLOW responses are never served from cache; DENY cache entries expire at the
   TTL.
4. Config tests: `http://` is rejected; any `fail_open` or `skip_verify` style key
   is rejected; a URL resolving to loopback, RFC 1918, link-local or
   169.254.169.254 is refused at connect time.
5. Canary test: secret and token values never appear in events, error strings,
   `%v`/`%+v` output or logs.
