// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package hostkeypolicy validates the upstream SSH host key policy values
// (pinned host keys and host CA) that a target may carry. It is pure
// validation: it is not wired to the API or the database.
package hostkeypolicy

import (
	"bytes"
	stdctx "context"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"golang.org/x/crypto/ssh"
)

const (
	// MaxHostKeys is the maximum number of pinned host keys.
	MaxHostKeys = 16
	// MaxEntryLength is the maximum length in bytes of a single entry.
	MaxEntryLength = 4 * 1024
	// MinRSABits is the minimum accepted RSA modulus size.
	MinRSABits = 3072
)

// HostKeyAlgorithms is the list of host key algorithms the upstream SSH
// client must pin. It never contains the SHA-1 based ssh-rsa.
var HostKeyAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
}

// ValidateHostKeys vets a list of pinned host keys in authorized_keys format.
func ValidateHostKeys(keys []string) error {
	const op = "hostkeypolicy.ValidateHostKeys"
	if len(keys) > MaxHostKeys {
		return errors.New(stdctx.Background(), errors.InvalidParameter, op, fmt.Sprintf("too many host keys: %d (max %d)", len(keys), MaxHostKeys))
	}
	seen := make(map[string]struct{}, len(keys))
	for i, k := range keys {
		pub, err := parseEntry(k)
		if err != nil {
			return errors.New(stdctx.Background(), errors.InvalidParameter, op, fmt.Sprintf("host key %d: %s", i, err))
		}
		fp := ssh.FingerprintSHA256(pub)
		if _, dup := seen[fp]; dup {
			return errors.New(stdctx.Background(), errors.InvalidParameter, op, fmt.Sprintf("host key %d: duplicate key %s", i, fp))
		}
		seen[fp] = struct{}{}
	}
	return nil
}

// ValidateHostCA vets a single host CA public key in authorized_keys format.
func ValidateHostCA(ca string) error {
	const op = "hostkeypolicy.ValidateHostCA"
	if _, err := parseEntry(ca); err != nil {
		return errors.New(stdctx.Background(), errors.InvalidParameter, op, fmt.Sprintf("host ca: %s", err))
	}
	return nil
}

// parseEntry parses and vets one authorized_keys style entry. Returned errors
// never contain key material.
func parseEntry(entry string) (ssh.PublicKey, error) {
	if strings.TrimSpace(entry) == "" {
		return nil, fmt.Errorf("entry is empty")
	}
	if len(entry) > MaxEntryLength {
		return nil, fmt.Errorf("entry exceeds %d bytes", MaxEntryLength)
	}
	for _, r := range strings.TrimSpace(entry) {
		if r < 0x20 || r == 0x7f {
			return nil, fmt.Errorf("entry contains control characters")
		}
	}
	if strings.ContainsAny(entry, "*?") {
		return nil, fmt.Errorf("entry contains wildcards")
	}
	pub, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(entry))
	if err != nil {
		return nil, fmt.Errorf("entry is not a valid public key")
	}
	if len(options) > 0 {
		return nil, fmt.Errorf("key options are not allowed")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("entry must contain exactly one key")
	}
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
	case ssh.KeyAlgoRSA:
		cpk, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("unsupported key %s", ssh.FingerprintSHA256(pub))
		}
		rpk, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rpk.N.BitLen() < MinRSABits {
			return nil, fmt.Errorf("rsa key %s is smaller than %d bits", ssh.FingerprintSHA256(pub), MinRSABits)
		}
	default:
		return nil, fmt.Errorf("unsupported key type %q for key %s", pub.Type(), ssh.FingerprintSHA256(pub))
	}
	return pub, nil
}
