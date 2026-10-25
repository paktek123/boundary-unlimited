// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package hostkey builds an ssh.HostKeyCallback from a policy of pinned host
// keys and/or trusted host certificate authorities. It is fail-closed:
// trust-on-first-use is not supported and an empty policy rejects every key.
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

// New returns an ssh.HostKeyCallback enforcing p. Any entry that cannot be
// parsed causes an error: a partially applied policy is never returned.
func New(p Policy) (ssh.HostKeyCallback, error) {
	const op = "hostkey.New"
	pinned := make([]ssh.PublicKey, 0, len(p.PinnedKeys))
	for i, s := range p.PinnedKeys {
		k, err := parse(s)
		if err != nil {
			return nil, errors.Wrap(context.Background(), err, op, errors.WithMsg("pinned key %d", i), errors.WithCode(errors.InvalidParameter))
		}
		if _, ok := k.(*ssh.Certificate); ok {
			return nil, errors.New(context.Background(), errors.InvalidParameter, op, fmt.Sprintf("pinned key %d is a certificate; use HostCAs", i))
		}
		pinned = append(pinned, k)
	}
	cas := make([]ssh.PublicKey, 0, len(p.HostCAs))
	for i, s := range p.HostCAs {
		k, err := parse(s)
		if err != nil {
			return nil, errors.Wrap(context.Background(), err, op, errors.WithMsg("host CA %d", i), errors.WithCode(errors.InvalidParameter))
		}
		cas = append(cas, k)
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

func parse(s string) (ssh.PublicKey, error) {
	k, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("unexpected trailing data")
	}
	return k, nil
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
