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

## Not yet available

The `injected_application` purpose on `ssh` targets (issue #5), static
`ssh_private_key` injection in the worker (issue #7), the Vault SSH
certificate library for injection (issue #8) and the matching CLI flag.
