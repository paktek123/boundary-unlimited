// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package kms

// redacted is what Keys prints for every formatting verb.
const redacted = "kms.Keys{redacted}"

// String never prints key material: Keys holds plaintext BSR and private keys,
// so printing it with %v, %+v or %s would leak them into logs and errors.
func (k *Keys) String() string { return redacted }

// GoString redacts the keys for %#v.
func (k *Keys) GoString() string { return redacted }
