# Licensing notice

Boundary Unlimited is a community-maintained fork of HashiCorp Boundary. The
repository contains two kinds of code, and they are licensed differently.

## Code written for this fork: MIT

Files that were written from scratch for this fork carry the header

```go
// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT
```

and are licensed under the MIT License. The license text is in
[`LICENSE`](LICENSE) (the repository's license file) and in
[`LICENSES/MIT.txt`](LICENSES/MIT.txt). At the time of writing these are the Go
files in:

- `internal/accessrequest`
- `internal/runbook` (including `source` and `approval`)
- `internal/masking`
- `internal/guardrails`
- `internal/policyhook`
- `internal/notify` (including `slack` and `teams`)
- `internal/event/syslogfmt`
- `internal/event/sinkqueue`
- `internal/daemon/worker/recording/{finalize,scratch,upload,bsrfs}`
- `internal/daemon/worker/proxy/ssh` and `internal/daemon/worker/proxy/kube`
- `internal/bsr/playback` and `internal/bsr/ssh/recorder`
- in `internal/cmd/commands/connect`: `kube_credentials*.go`, `kubeconfig*.go`,
  `ssh_known_hosts*.go`, `ssh_pinned*.go` and the `kubecreds` package

## Upstream code: original license

Everything else is upstream HashiCorp Boundary code, or adapted from it, and
keeps its original copyright header and license:

- Most files are copyright IBM Corp. under the Business Source License 1.1
  (SPDX `BUSL-1.1`), with IBM Corp. as Licensor. The files under `api/`, `sdk/`
  and the other paths marked as MPL-2.0 in `.copywrite.hcl` are under the
  Mozilla Public License 2.0.
- The MIT License in this repository cannot change the license of those files.
  Only their copyright holder can do that. Their headers must not be removed or
  changed.
- The text of the Business Source License 1.1 that was the repository's
  `LICENSE` before the MIT text replaced it is available from git history
  (`git show 7709ad649^:LICENSE`) and at <https://mariadb.com/bsl11/>.
- Files adapted from upstream files (for example the `ssh` and `rdp` target
  types, which are copied from the `tcp` target type, and their handlers) are
  derivative works and also keep the upstream headers.

## New files

A new file gets the MIT header above only if it is original to this fork. A file
that is copied or adapted from an upstream file keeps the upstream header. When
you add a new package of original files, add it to the list above and to
`header_ignore` in `.copywrite.hcl`, so that `copywrite headers` does not rewrite
the headers.
