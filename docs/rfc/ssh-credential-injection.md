# RFC: Credential injection for `ssh` targets

Status: Draft  
Tracking: epic #1, issue #4  
Implemented by: #5, #6, #7, #8, #9 (none merged yet)

## Summary

Allow `ssh` targets to *inject* credentials at the worker so the client never
sees the secret. Today `ssh` (and `rdp`) targets accept only the `brokered`
purpose; `ssh.Target.VetCredentialSources` in `internal/target/ssh/register.go`
rejects every other purpose.

## Non-goals

* RDP injection (separate epic).
* Session recording (epic #2); the injection proxy is designed so the recording
  epic can tap the channel stream, but nothing here records.

## Purpose and API

The credential purpose is the existing `credential.InjectedApplicationPurpose`
(`injected_application`, `internal/credential/credential.go`). The API
surface is the existing credential-source fields on targets; no new target
fields are introduced:

* `injected_application_credential_source_ids` on `ssh` targets
  (`add-credential-sources`, `set-credential-sources`,
  `remove-credential-sources`), plus the matching `boundary targets` CLI flag
  and SDK field (issue #9).
* A target may have at most one injected credential source (or one static/
  library set that resolves to a single credential). Combining an injected
  credential with brokered ones is allowed; brokered ones are still returned to
  the client.

## Supported credential types

| Source | Credential | SSH auth method |
| --- | --- | --- |
| Static | `username_password` | password (and keyboard-interactive answering the password prompt) |
| Static | `ssh_private_key` (optional passphrase) | public key |
| Vault library | `vault-ssh-certificate` | public key + OpenSSH user certificate |

`json` and `username_password_domain` credentials are rejected for injection.
Library-based injection reuses the existing `vault-ssh-certificate` library
(`internal/credential/vault/ssh_certificate_credential_library.go`); the
private key is generated per session by the library and the certificate is
signed by Vault, so no long-lived key material is stored for that case.

## Worker flow

1. The client connects to the worker proxy as for any ssh session. The
   controller returns the session authorization and, for injected sources,
   the credentials are fetched by the controller (`ApplicationCredentials`
   purpose) and sent to the **worker only**, over the existing worker<->controller
   authenticated connection. They are never included in the response to the
   client.
2. The worker terminates the client's SSH connection with a worker-held server
   host key and accepts the client without further authentication; the
   Boundary session authorization already authenticated the user. (The worker
   is the SSH server as seen by the client.)
3. The worker dials the target and authenticates as an SSH *client* using the
   injected credential (password, key, or key+certificate), then bridges
   channels, requests and global requests between the two sides.
4. On session end, cancel, or expiry the worker closes both legs and discards
   the credential from memory. Credentials are held only in process memory,
   never logged, never written to disk, and never included in worker events.

Because the worker presents its own host key to the client, the client's
`known_hosts` entry refers to the worker, not the target (see below).

## Host key verification

Two independent trust decisions exist:

* **Worker to target.** The worker must verify the target's host key. Trust-on-first-use is
  not acceptable for a security feature, so injection is **fail-closed**: a target must supply the expected host key(s) (or a
  trusted host CA) and the worker rejects mismatches. Where to store these
  (target attribute vs. host/host-catalog attribute) is the main open question
  below; until it is resolved and implemented, injection must not be enabled.
* **Client to worker.** The worker host key is stable per worker/target pair
  so users can verify it. The CLI (`boundary connect ssh`) already sets
  `HostKeyAlias` to the host/target id (`internal/cmd/commands/connect/ssh.go`),
  which keeps `known_hosts` entries per target rather than per `127.0.0.1:port`.
  The worker host key is derived/stored so it is identical across sessions to the
  same target and is distributed to the user as part of session authorization
  info so the CLI can pin it.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| Credential cannot be retrieved at session creation (Vault down, revoked) | Session creation fails; no fallback to brokered/no-auth. |
| Target host key mismatch or unknown | Worker closes the client connection with a clear error; event emitted (no secret). |
| Upstream auth rejected | Client connection closed with an auth error; event emitted. |
| Unsupported credential type for target | Rejected at API validation. |
| Worker lacks injection support (older worker) | Session creation fails; never degrades to unauthenticated or brokered. |
| Credential expires/revoked mid-session (Vault lease) | Existing session continues until lease/session policy ends; session is terminated on lease revocation as for brokered Vault credentials. |

## Security requirements (enforcement-first)

* The `injected_application` purpose must not be accepted by
  `ssh.Target.VetCredentialSources` until the worker proxy (#6) that actually
  injects it, and the host-key verification above, exist in the same or an
  earlier merged change. The API and validation change (#5) must therefore not
  land before, or without, #6.
* Secrets must be redacted from logs, events and error strings.
* Injection must be fail-closed at every step above.

## Suggested implementation order

1. #6 worker SSH proxy with username/password plus host key verification
   (enforcing code), together with enabling the purpose (#5), or #5 behind a
   "not yet supported" error until #6 merges.
2. #7 static `ssh_private_key` (+ passphrase).
3. #8 Vault SSH certificate library.
4. #9 CLI, docs, CHANGELOG.

## Open questions

* Where target host keys / host CAs are configured (new target field vs. host
  attribute). Needs a schema decision and migration; to be decided before #6.
* Whether the worker presents a per-worker or per-target host key to clients.
* Whether to support `keyboard-interactive` beyond password prompts.
