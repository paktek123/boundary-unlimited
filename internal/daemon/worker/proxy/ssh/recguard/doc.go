// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

/*
Package recguard implements the fail-closed failure mode for SSH session
recording: when writing recorded channel data fails for any reason (write
error, quota exceeded, short write), the session is terminated, the recording
is marked incomplete, and no further data is ever written to the sink.

This is a leaf library. It is not wired into the worker; the recorder and the
scratch store satisfy the small consumer-side interfaces defined here.
Errors and termination reasons produced by this package never contain channel
data or the text of the underlying sink error.
*/
package recguard
