# SSH credential injection (status and operator notes)

Tracking: epic #1, issue #9. Design: [docs/rfc/ssh-credential-injection.md](rfc/ssh-credential-injection.md).

> **Status: not available yet.** `ssh` targets still accept only the
> `brokered` credential purpose: `ssh.Target.VetCredentialSources`
> (`internal/target/ssh/register.go`) rejects every other purpose, so no
> configuration can request injection. The worker-side pieces are merged as
> libraries only. This page records what exists and the properties the
> feature must keep; it will be updated when injection can be enabled.

## What is merged (libraries only)

| Area | Package |
|---|---|
| Credential material to `x/crypto/ssh` auth methods (password, private key, certificate); strict parsing, errors never contain secrets | `internal/daemon/worker/proxy/ssh/injectauth` |
| SSH proxy handler and upstream dialing | `internal/daemon/worker/proxy/ssh` |
| Host key verification policy | `internal/daemon/worker/proxy/ssh/hostkey`, `internal/target/ssh/hostkeypolicy` |

## Worker session input

The ssh worker handler argument is the `SshSessionInput` message
(`internal/proto/controller/servers/services/v1/ssh_session_input.proto`),
decoded by `DecodeSessionInput` in
`internal/daemon/worker/proxy/ssh/session_input.go`. It carries the session,
connection and target ids, the resolved upstream address, the pinned host keys
or host CAs, a recording flag and the expiration. It has deliberately **no
credential field**. The decoder fails closed: it refuses the session when the
message is missing or malformed, when its connection id does not match the
connection being proxied, when neither a pinned host key nor a host CA is
present, or when there are more than `hostkeypolicy.MaxHostKeys` entries.

The controller does not populate this message yet: an `ssh` target has no
stored host key policy (tracked on issue #347), so no input is sent and the decoder
refuses every ssh session until that lands.

## Properties the feature keeps

* **The client never sees injected secrets.** Only brokered credentials are
  returned to the client.
* **Fail closed.** Unparsable or unusable credential material, or a failed
  upstream authentication, refuses the session; there is no fallback to
  another method.
* **Host keys are verified** against the target's host key policy before any
  credential is sent; there is no "trust on first use" bypass.
* **No secrets in errors or logs.** Passwords, passphrases and key bytes are
  never printed; callers zero their copies after use.
* **Supported credential types:** `username_password`, `ssh_private_key`
  (optional passphrase) and the Vault `vault-ssh-certificate` library
  (planned, issue #8). `json` and `username_password_domain` are rejected.

## Worker authentication library (not yet reachable)

The worker package `internal/daemon/worker/proxy/ssh/injectauth` turns a
credential into upstream SSH authentication methods and is used by
`NewClientUpstream` (`upstream.go`). It supports a password, a private key with
an optional passphrase, and a private key with an OpenSSH certificate. It fails
closed with fixed-reason errors: a certificate without its key, an encrypted
key without a passphrase, an unparsable key, an unsupported key type or an RSA
key shorter than the minimum are all refused, and no key bytes appear in
errors. This is a library only: no ssh target can reach it yet because the
controller neither accepts the injected purpose on ssh targets nor sends a host
key policy (see below), so it does not change what a session can do today.

## Not yet available

The `injected_application` purpose on `ssh` targets (issue #5), wiring static
`ssh_private_key` injection end to end (issue #7; the worker library above
exists), the Vault SSH certificate library for injection (issue #8) and the
matching CLI flag.
