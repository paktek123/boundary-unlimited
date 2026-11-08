# Licensing notice

Boundary Unlimited is a community-maintained fork of HashiCorp Boundary. Most
of the repository is upstream code, and its licensing is unchanged:

- Upstream code keeps its original copyright headers and its original license
  (see [`LICENSE`](LICENSE), the Business Source License 1.1 with IBM Corp. as
  Licensor, and the MPL-2.0 files under `api/`, `sdk/` and the other paths listed
  in `.copywrite.hcl`). Those headers must not be removed or changed.
- Files adapted from upstream code (for example the `ssh` and `rdp` target types,
  which are copied from the `tcp` target type) are derivative works and also keep
  the upstream headers.

Files that were written from scratch for this fork carry the header

```go
// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT
```

and are licensed under the MIT License (see [`LICENSES/MIT.txt`](LICENSES/MIT.txt)).
At the time of writing these are the Go files in:

- `internal/accessrequest`
- `internal/runbook` (including `source` and `approval`)
- `internal/masking`
- `internal/guardrails`
- `internal/notify` (including `slack` and `teams`)
- `internal/event/syslogfmt`
- `internal/event/sinkqueue`
- `internal/daemon/worker/recording/{finalize,scratch,upload,bsrfs}`

The repository as a whole is distributed under the terms of the upstream
license, because it contains and builds on upstream code. The MIT header only
describes the license of the individual file it appears in.

New files get the MIT header above only if they are original to this fork. A
file that is copied or adapted from an upstream file keeps the upstream header.
