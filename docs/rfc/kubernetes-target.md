# RFC: `kubernetes` target type

Status: Draft  
Tracking: epic #22, issue #23  
Implemented by: #24, #25, #26, #27 (none merged yet)

## Summary

Add a `kubernetes` target subtype so users can reach a Kubernetes API server
through a Boundary worker with the usual session authorization, host sources
and credential brokering, and use `kubectl` via `boundary connect kube`.

## How `ssh` and `rdp` were added (the pattern to mirror)

A subtype consists of: a store proto and `target_<type>` table migration; a
package under `internal/target/<type>/` (`register.go`, `target.go`,
`testing.go`, repository tests); a handler under
`internal/daemon/controller/handlers/targets/<type>`; blank imports in
`cmd/boundary/package_registry_oss.go`; SDK/CLI generation (gencli); and, for
`ssh`/`rdp`, a `VetCredentialSources` hook limiting credential purposes. The
`kubernetes` subtype follows the same layout, copying `internal/target/rdp/`
(closest: no worker-side protocol handling today).

## Address model

Same as other host-based targets: either an `address` on the target or one or
more host sources (static host catalogs, dynamic plugins). Default port
**6443** when `default_port` is not set. An alias works as for ssh/rdp.

## Proxy flow

The API server speaks TLS (HTTP/2 and HTTP/1.1 including upgrade/streaming for
`exec`, `attach`, `port-forward` and watches). The worker must therefore be a
**TLS-transparent byte proxy** by default:

1. `boundary connect kube` starts a local listener (as `boundary connect`
   does) and writes a temporary kubeconfig pointing at
   `https://127.0.0.1:<port>`.
2. The worker opens a TCP connection to the API server and relays bytes (the
   existing `internal/daemon/worker/proxy/tcp` path). TLS is end to end between
   `kubectl` and the API server; the worker never sees plaintext or tokens.
3. Server name: the API server certificate is not issued for `127.0.0.1`. The
   generated kubeconfig sets `tls-server-name` to the target address (or a
   configured name) so verification still succeeds against the real
   certificate. The CA bundle is taken from the brokered kubeconfig/credential
   when present, otherwise the client's own trust store is used. TLS
   verification is never disabled by default; `insecure-skip-tls-verify` is
   not generated.

Terminating TLS at the worker (for injection or audit of API calls) is a
separate, later design and out of scope. This keeps v1 free of any
"setting that does nothing" risk: no capability beyond brokering is accepted.

## Credentials

Only the `brokered` purpose is accepted in v1; `VetCredentialSources` rejects
all others, exactly as for ssh/rdp today. Supported brokered credential shapes:

| Credential | Use |
| --- | --- |
| `json` containing a bearer `token` | `user.token` in the generated kubeconfig |
| `json` with `client-certificate-data` / `client-key-data` | client cert auth |
| `json` containing a complete kubeconfig | used as is, with the `server` rewritten to the local listener and `tls-server-name` set |

Vault generic libraries (for example Vault's Kubernetes secrets engine) can
produce short-lived tokens via `json` credentials. No new credential types are
needed for v1. Credentials are exposed to the client when brokered; the docs
(#27) must say so.

## `boundary connect kube`

Mirrors `internal/cmd/commands/connect/` helpers (`ssh.go`, `rdp`): authorize
session, start proxy, write a mode `0600` kubeconfig in a private temp dir,
run `kubectl` with `KUBECONFIG` set (arguments after `--`), and remove the file
on exit. Credentials from the session are merged into the file; they are never
printed to stdout unless the user passes the existing credential-display flags.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| Certificate does not match `tls-server-name` | `kubectl` fails with a TLS error; Boundary does not downgrade verification. |
| Token expired/revoked | API server returns 401; user re-authorizes a session. |
| Unsupported credential shape | `connect kube` errors clearly before launching `kubectl`. |
| Purpose other than `brokered` | Rejected at API validation. |

## Suggested implementation order

1. #24 migration, store protos, domain subtype (generated code needs the repo's
   protobuf tooling).
2. #25 API handler, SDK, CLI.
3. #26 `boundary connect kube` (the proxy itself reuses the tcp worker path).
4. #27 docs and CHANGELOG.

## Open questions

* Whether the kubeconfig in `json` credentials should be an official credential
  type later.
* Support for exec-plugin based kubeconfigs (not supported; they run arbitrary
  local commands and are refused).
