// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package hostkey builds an ssh.HostKeyCallback from a policy of pinned host
// keys and/or trusted host certificate authorities. It is fail-closed:
// trust-on-first-use is not supported and an empty or invalid policy is an
// error (see Validate).
package hostkey

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"net"

	"github.com/hashicorp/boundary/internal/errors"
	"golang.org/x/crypto/ssh"
)

// ErrHostKeyMismatch is returned (wrapped) when the key presented by a host is
// not trusted by the policy. Use errors.Is to test for it.
var ErrHostKeyMismatch = stderrors.New("host key is not trusted by policy")

// Policy describes which host keys are trusted. Entries use the
// authorized_keys wire format, e.g. "ssh-ed25519 AAAA...". The zero value
// trusts nothing.
type Policy struct {
	// PinnedKeys are host public keys that are trusted exactly.
	PinnedKeys []string
	// HostCAs are public keys of certificate authorities trusted to sign
	// host certificates.
	HostCAs []string
}

// New returns an ssh.HostKeyCallback enforcing p. The policy must pass
// Validate: any invalid entry, including an empty policy, causes an error and
// a partially applied policy is never returned.
func New(p Policy) (ssh.HostKeyCallback, error) {
	const op = "hostkey.New"
	pinned, cas, err := validate(p)
	if err != nil {
		return nil, errors.Wrap(context.Background(), err, op)
	}

	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return isIn(auth, cas)
		},
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if cert, ok := key.(*ssh.Certificate); ok {
			if len(cas) == 0 {
				return mismatch(hostname)
			}
			if err := checker.CheckHostKey(hostname, remote, cert); err != nil {
				return mismatch(hostname)
			}
			return nil
		}
		if isIn(key, pinned) {
			return nil
		}
		return mismatch(hostname)
	}, nil
}

func isIn(k ssh.PublicKey, set []ssh.PublicKey) bool {
	kb := k.Marshal()
	for _, c := range set {
		if bytes.Equal(kb, c.Marshal()) {
			return true
		}
	}
	return false
}

func mismatch(host string) error {
	return fmt.Errorf("host %q: %w", host, ErrHostKeyMismatch)
}
