# Kubernetes target (status and operator notes)

Tracking: epic #22, issue #27. Design: [docs/rfc/kubernetes-target.md](rfc/kubernetes-target.md).

> **Status: targets can be created, but kubernetes sessions are not usable.**
> The `kubernetes` target type and its controller handler are registered in the
> controller binary (`internal/daemon/controller/handlers/targets/kubernetes`),
> so the API can create, read, update and list kubernetes targets with
> `default_port` (default 443) and `default_client_port`. The worker relay has
> no session input decoder installed, so it refuses every kubernetes session
> before relaying any byte (issue #26). There are no recording or credential
> injection options; credential sources are limited to the `brokered` purpose.
> The SDK attribute options and the CLI commands are separate open PRs (#328,
> #329).

## What is merged (not enabled)

| Area | Location |
|---|---|
| Target subtype package (store, repository tests) | `internal/target/kubernetes` |
| Inert `target_kubernetes` table (migration 113) | `internal/db/schema/migrations/oss/postgres` |
| Worker relay to a Kubernetes API server over mandatory, verified TLS; registered as a proxy handler that refuses every session (fail closed) until a session input decoder is installed | `internal/daemon/worker/proxy/kube` |
| Kubeconfig builder: TLS-verifying, written to a private 0600 temp file, exec-plugin kubeconfigs rejected | `internal/cmd/commands/connect` (`kubeconfig.go`) |
| Parsing of a brokered Kubernetes credential for `boundary connect kube` | `internal/cmd/commands/connect/kubecreds` |

## Properties the feature keeps

* **Verified TLS only.** The worker relay and the generated kubeconfig always
  verify the API server certificate; there is no `insecure-skip-tls-verify`
  option.
* **No exec plugins.** A kubeconfig that runs an external command is rejected,
  so a credential cannot make the client run programs.
* **Private local files.** Generated kubeconfigs are created with mode 0600 and
  removed when the connection ends.
* **Credentials are brokered**, not stored in the kubeconfig by the target.

## Not yet available

The SDK options and `boundary targets create kubernetes` (issue #25, PRs #328
and #329), the session input decoder that lets the registered worker proxy relay a session,
and the `boundary connect kube` flags (issue #26). Until the decoder exists
the registered handler (`internal/daemon/worker/proxy/kube/register.go`)
refuses every session before relaying any byte.
