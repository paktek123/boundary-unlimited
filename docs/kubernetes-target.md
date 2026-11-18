# Kubernetes target (status and operator notes)

Tracking: epic #22, issue #27. Design: [docs/rfc/kubernetes-target.md](rfc/kubernetes-target.md).

> **Status: not available yet.** The `kubernetes` target type is not
> registered: nothing outside `internal/target/kubernetes` imports it, so the
> API, SDK and CLI cannot create one and no session can be authorized for it.
> The pieces below are merged as libraries or inert database schema only. This
> page will be updated when the target type can be used.

## What is merged (not enabled)

| Area | Location |
|---|---|
| Target subtype package (store, repository tests) | `internal/target/kubernetes` |
| Inert `target_kubernetes` table (migration 113) | `internal/db/schema/migrations/oss/postgres` |
| Worker relay to a Kubernetes API server over mandatory, verified TLS; not registered as a proxy handler | `internal/daemon/worker/proxy/kube` |
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

The API handler, SDK and `boundary targets create kubernetes` (issue #25), the
registered worker proxy and the `boundary connect kube` flags (issue #26).
