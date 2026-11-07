// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package source

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

// ErrHashMismatch is returned when script bytes differ from the recorded pin.
var ErrHashMismatch = errors.New("source: script hash does not match the recorded pin")

// Pin records what was fetched: the commit and the SHA-256 of the exact script
// bytes. It holds no script content.
type Pin struct {
	SHA          string // full lowercase 40-hex commit SHA
	ScriptSHA256 string // lowercase hex SHA-256 of the script bytes
}

// NewPin returns the Pin for script bytes fetched at sha.
func NewPin(sha string, script []byte) (Pin, error) {
	if err := ValidateSHA(sha); err != nil {
		return Pin{}, err
	}
	sum := sha256.Sum256(script)
	return Pin{SHA: sha, ScriptSHA256: hex.EncodeToString(sum[:])}, nil
}

// Verify re-checks script against the pin. Call it immediately before
// execution (TOCTOU). It fails closed on an invalid pin, an empty hash or any
// mismatch.
func Verify(pin Pin, script []byte) error {
	if err := ValidateSHA(pin.SHA); err != nil {
		return err
	}
	want, err := hex.DecodeString(pin.ScriptSHA256)
	if err != nil || len(want) != sha256.Size {
		return ErrHashMismatch
	}
	got := sha256.Sum256(script)
	if subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return ErrHashMismatch
	}
	return nil
}
