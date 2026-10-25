// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

/*
Package playback implements the "unvalidated content is never trusted" rule
for exporting session recordings: a BSR is validated first, and only then
converted. If validation fails, or the recording is reported invalid or
incomplete, nothing is written to the destination. Converter output is
buffered, so a failure part-way through conversion is reported as an error and
is never presented as a successful export.

This is a leaf library with consumer-side interfaces. Adapters around
bsr.Validate and the convert package are supplied by the caller, and nothing
is wired to a command yet. Errors never contain recording content, because
recordings can contain secrets such as typed passwords.
*/
package playback
