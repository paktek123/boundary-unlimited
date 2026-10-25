# Boundary Unlimited release process

Releases are small, regular and mostly automatic, with a human approving each one by
merging a release pull request.

## When a release happens

A release is prepared once, since the previous release, the merged pull requests contain at
least:

* **3 major changes**, and
* **5 minor changes or bug fixes**.

Pull requests are classified by reading what they actually change, not what they say about
themselves:

| Class | What counts |
|---|---|
| **Major** | A user-visible capability that works end to end on `main`: a new target type that can be created and used, a new auth method, a new CLI command, a security control that is now enforced end to end, a previously rejected setting that is now supported, or the pull request that wires up and enables a feature built in earlier pieces. |
| **Minor** | A user-visible improvement, a bug fix, a hardening change that alters behaviour, a new option or flag, an API addition, performance work, or documentation for behaviour that already shipped. |
| **Not counted** | Design RFCs and documentation about features that have not shipped, internal groundwork that nothing calls yet, CI, test-only and refactoring changes, and release pull requests. |

Groundwork that is not wired up does not count until the pull request that enables it merges.

## Version numbers

Semantic versioning. A release that contains major changes bumps the **minor** number
(`0.22.0` after `0.21.x`). The next version is computed from the highest of the latest
`v*` release tag, `version/VERSION` and the newest released section in `CHANGELOG.md`.

## How it works

1. The **release manager routine** reads the pull requests merged since the last release,
   classifies them and keeps a **Release tracker** issue up to date with the counts.
2. When both thresholds are met it opens a pull request `Release vX.Y.Z` from the branch
   `claude/release-vX.Y.Z`. That pull request only changes:
   * `version/VERSION` to `X.Y.Z`, and
   * `CHANGELOG.md`: the `Unreleased (Boundary Unlimited)` section becomes
     `## X.Y.Z (YYYY/MM/DD)`, grouped into major and minor changes, and a fresh empty
     `Unreleased` section is added above it.
3. The normal code and security reviews and CI run on that pull request.
4. **A human merges it.** That merge is the approval to publish.
5. The `release` workflow (`.github/workflows/release.yml`) runs because `version/VERSION`
   changed on `main`. It checks that the version is valid, that the changelog has a section
   for it and that the release does not exist yet, builds binaries for
   linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64, writes
   `SHA256SUMS`, and creates the GitHub release and tag `vX.Y.Z` with the changelog section
   as the release notes.

## Manual runs

`release` can be started by hand from the Actions tab. With `dry_run` (the default for manual
runs) it builds and packages everything but does not create a release, which is the safe way
to check the pipeline.

## Changing the rules

The thresholds (3 major, 5 minor) and the classification above are enforced by the release
manager routine's prompt. Change them there and update this document.
