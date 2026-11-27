# SSH session recording (status and operator notes)

Tracking: epic #2, issue #14. Design: [docs/rfc/ssh-session-recording.md](rfc/ssh-session-recording.md).

> **Status: not available yet.** The worker-side building blocks are merged
> as libraries, but nothing turns recording on. The API and CLI still refuse
> `enable_session_recording` and `storage_bucket_id` on `ssh` targets
> (issue #11), and the worker does not install the recording factory (issues
> #243, #259, #289, #290, #291). This page describes what exists and the
> properties the final feature must keep, so operators are not surprised by
> them. It will be updated when recording can be enabled.

## What is merged (libraries only)

| Area | Package |
|---|---|
| BSR container format, checksums, signatures, `bsr.Validate` | `internal/bsr` |
| SSH channel recorder | `internal/bsr/ssh/recorder` |
| Recording factory and fail-closed guard around the SSH proxy | `internal/daemon/worker/proxy/ssh` (`recordingfactory.go`, `recguard`) |
| Local scratch store with quota, recovery of orphaned recordings | `internal/daemon/worker/recording/scratch` |
| Finalisation and verified upload | `internal/daemon/worker/recording/{finalize,upload}` |
| Session storage bucket source: `NewSessionBucketSource` resolves the per-session bucket from controller-provided data; any missing lookup, opener or bucket refuses the session with the fixed `ErrRecordingBucketUnavailable`, and the bucket credential is redacted from formatting and JSON. Not installed: the production lookup `NewLookupSessionBucketLookup` (`internal/daemon/worker/recording_bucket_lookup.go`) exists but no production opener does, and nothing installs the source yet (issue #348) | `internal/daemon/worker/recording_bucket_source.go` |

## Properties the feature keeps

* **Opt-in per target.** Recording is never on by default.
* **Fail closed.** If recording is required and the factory, scratch store or
  keys cannot be set up, the session is refused before any data is relayed. If
  scratch fills or a write fails mid-session, the session is terminated and
  the recording is marked incomplete rather than continuing unrecorded.
* **Validated before upload, kept until verified.** `bsr.Validate` runs before
  upload; scratch data is deleted only after a verified upload. After a worker
  restart, orphaned recordings are uploaded or discarded and marked incomplete.
* **Per-session keys.** Each recording uses its own keys, wrapped by the
  worker's `bsr`-purpose KMS wrapper; key bytes are never printed or logged.
* **Credentials in memory only.** Storage bucket credentials are supplied per
  session and are never written to scratch, config files or logs.

## Things operators must know

* **Terminal input can contain secrets** (passwords typed into a session,
  pasted tokens). A recording is a protocol-level channel log and captures
  them. Treat recordings and the storage bucket as sensitive, restrict who can
  read them and set a retention period.
* Recording requires the worker to terminate and re-originate the SSH
  connection (the same proxy used for credential injection); plain TCP
  proxying cannot record SSH.
* Scratch space is bounded by a quota; size it for your longest sessions.

## Worker install gate

`worker.New` calls `installSSHRecording`, which installs the ssh recording
factory only when every dependency exists. The startup event names a missing
dependency by these classes: `recording_storage_path` (the scratch store),
`finalizer`, `bsr_kms_wrapper` (the spec provider) and `reporter`. Today no
production spec provider, finalizer or reporter is built, so the factory stays
uninstalled, the worker emits one startup event naming the missing classes (the
scratch store is supplied whenever `recording_storage_path` is configured, so
`recording_storage_path` is named only when it is not), and
any session that requires recording is refused before an upstream connection
is made. There is no configuration field that enables recording yet.

## Not yet available

Enabling recording on a target, upload to a storage bucket from a running
worker, registering the session recording record, and CLI playback/export of
SSH recordings.

The export pipeline exists only as an internal library
(`internal/bsr/playback`). It validates a recording first and converts it
(asciicast v2 for shell channels, raw log otherwise) only if the recording is
valid and complete; on any failure nothing is written.

The CLI commands exist in this fork: `boundary session-recordings export`
(create, read, list, cancel) and `boundary session-recordings download`. They
call the `SessionRecordingService` API, but the open-source controller's
handler (`internal/daemon/controller/handlers/session_recordings`) returns
`Unimplemented` ("session recordings are an Enterprise-only feature") for
get, list, download, export and delete. So no playback or export is served by
this build, and the CLI commands fail with that error. Nothing in this section
changes what a worker records or uploads. Refs #14.

## Per-session bucket credential (not populated yet)

The `LookupSession` response now has an optional `recording_bucket` message
(bucket id plus a secret-classified credential), and the worker has
`NewLookupSessionBucketLookup` to read it into a redacting reference. The
controller does not populate the field and nothing installs the lookup, so
recording-required sessions are still refused. Operators should issue a
write-only, prefix-scoped bucket credential. Refs #363.
