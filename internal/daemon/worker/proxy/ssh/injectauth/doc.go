// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package injectauth converts the credential material the worker receives for
// an ssh target into golang.org/x/crypto/ssh authentication methods.
//
// Parsing is strict and fails closed: anything that is not clearly usable is
// an error, and error messages never contain passwords, passphrases or key
// bytes.
//
// The package is a leaf library and is not wired into the worker yet.
//
// Memory: AuthMethods does not retain the caller's byte slices. A private key
// is parsed into a ssh.Signer immediately (x/crypto copies what it needs), and
// the password is captured by the ssh.Password method as a string copy, as
// x/crypto requires. Callers should still zero their own slices once they are
// done with them.
package injectauth
