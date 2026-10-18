# RFC: SSH session recording and playback

Status: Draft  
Tracking: epic #2, issue #10  
Implemented by: #11, #12, #13, #14 (none merged yet)

## Summary

Record `ssh` sessions at the worker and make the recordings retrievable and
exportable. This RFC reuses what already exists in the tree instead of
inventing a new format:

* **Format:** the Boundary Session Recording (BSR) container library in
  `internal/bsr` (session, connection and channel containers, chunked,
  optionally compressed and encrypted, with checksums and signatures;
  `bsr.Session`, `Connection.NewChannel`, `bsr.Validate`).
* **Export:** `internal/bsr/convert` already contains an SSH converter
  (`convert/ssh.go`); asciicast-compatible export is built on that package.
* **Storage:** storage buckets (`internal/storage`, `internal/storage/plugin`,
  `boundary storage-buckets`) and the existing session recording resource and
  CLI (`internal/cmd/commands/sessionrecordingscmd`).

## Non-goals

* RDP recording.
* Credential injection (epic #1), although recording an injected session is
  the main use case (the worker terminates the SSH protocol there).

## Recording model

* One BSR session container per Boundary session, one connection container per
  proxied connection, one channel container per SSH channel.
* Channel data (both directions) and channel requests are stored as BSR
  messages/requests chunks. The recording is a protocol-level channel log, not
  a screen capture, so shell, exec, SFTP and port forwards are captured as the
  channel types they are.
* Capture requires the worker to terminate and re-originate the SSH protocol
  (the same proxy as credential injection, #6). Plain TCP proxying cannot
  record SSH because the payload is encrypted end to end. Recording therefore
  depends on that proxy and cannot ship before it.

## Storage

* The worker writes to local scratch storage while the session runs, then
  uploads the finished BSR to the target's storage bucket and the controller
  registers the session recording record (#13).
* Local scratch is bounded (configurable quota); when it fills, the session is
  terminated rather than continuing unrecorded (fail-closed).
* Scratch files are removed after a verified upload. A restarted worker uploads
  or discards orphaned partial recordings, marking them incomplete.

## Integrity and confidentiality

* BSR checksums and signatures use the BSR KMS keys (`internal/bsr/kms`);
  `bsr.Validate` runs before upload and is available for later verification.
* Data is encrypted with per-session keys wrapped by controller KMS, as BSR
  already supports; unwrapping happens on the controller side only.
* Terminal input can contain secrets typed into the session. This is inherent
  to recording; the docs (#14) must say so and the feature is opt-in per target.

## Retention

Retention of stored objects is delegated to the bucket's own lifecycle policy.
Boundary will not silently delete recordings. An explicit per-bucket retention
setting is a possible follow-up, out of scope here.

## API surface

No new fields: `enable_session_recording` and `storage_bucket_id` already exist
on the target model. Today `ssh`/`rdp` reject them (CHANGELOG, "Unreleased").
Enabling them (#11) is only valid once the worker really records (#12) and
uploads (#13) in the same release; otherwise a target would claim recording
that does not happen.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| Storage bucket unreachable at session start | Session creation fails (no unrecorded session). |
| Scratch full or write error mid-session | Session terminated; partial recording kept and marked incomplete. |
| Upload fails after session end | Retry with backoff; recording stays on scratch, reported pending, event emitted. |
| Worker without recording support | Session creation fails for recording-enabled targets. |
| Checksum/signature failure on read | CLI reports the container invalid; export refuses. |

## Playback and export

`boundary session-recordings` already lists and reads recordings. Playback and
export (#14) add a command that validates a BSR and streams it through
`internal/bsr/convert` to asciicast v2 for shell channels and to raw channel
logs for others. Unvalidated content is never trusted.

## Suggested implementation order

1. Shared SSH terminating proxy (epic #1, #6).
2. #12 channel capture to BSR on local storage (enforcing code).
3. #13 upload and registration.
4. #11 allow the target fields, in or after the PR that makes 2 and 3 work.
5. #14 CLI playback/export, docs, CHANGELOG.

## Open questions

* Scratch quota defaults and how they surface in worker config.
* Whether SFTP file contents are recorded or only metadata, given volume and
  sensitivity.
