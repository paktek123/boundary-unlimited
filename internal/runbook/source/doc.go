// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package source defines how a runbook script is obtained from a Git
// repository (see docs/rfc/runbooks.md, "Source of runbooks"). It holds the
// pinned-commit reference check, the Fetcher interface, the recorded Pin and
// the pre-execution hash verification. It contains no git or network code: the
// only Fetcher in this package is a fake for tests. The package is a pure
// library and nothing references it, so it enables nothing by itself.
//
// Contract for real Fetcher implementations (a later slice):
//   - use verified TLS or SSH only: host key or CA verification, never
//     trust-on-first-use, and no option to skip verification;
//   - fetch exactly the requested full commit SHA, never a branch or tag;
//   - never run hooks, checkout scripts, filters or submodule updates, and
//     never follow symlinks;
//   - return only the bytes of the single declared file;
//   - implement TreeCounter, so the file-count limit is enforced (Get refuses a
//     fetcher without it);
//   - stop reading at Limits.MaxScriptBytes instead of buffering an unbounded
//     blob, and stay within an overall timeout (honour ctx);
//   - run with a case-sensitive POSIX path model (the path checks do not
//     cover Windows short names or NTFS stream forms of ".git").
//
// ValidatePath rejects an element named "hooks" anywhere in the path, so a
// legitimate "scripts/hooks/run.sh" is refused; this is deliberately
// conservative.
package source
