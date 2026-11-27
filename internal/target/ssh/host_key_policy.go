// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target/ssh/hostkeypolicy"
	gossh "golang.org/x/crypto/ssh"
)

// hostKeySeparator joins the authorized_keys entries of one list in storage.
// No valid entry contains it: hostkeypolicy rejects control characters.
const hostKeySeparator = "\n"

// HostKeyPolicy returns the pinned host keys and host CAs stored on the
// target, in authorized_keys format. The policy lives on the target only:
// there is no other source and no trust on first use. Nothing accepts the
// policy through the API yet.
//
// Both lists are validated again on every read. Any inconsistency in the
// stored value is an error, never an empty or partial policy. Two empty lists
// with a nil error mean that no policy is stored; a consumer that needs a
// policy must refuse that case.
func (t *Target) HostKeyPolicy(ctx context.Context) (keys, cas []string, err error) {
	const op = "ssh.(Target).HostKeyPolicy"
	keys = splitEntries(t.GetHostKeyPolicyKeys())
	cas = splitEntries(t.GetHostKeyPolicyCas())
	if err := validateHostKeyPolicy(ctx, keys, cas); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("stored host key policy is invalid"))
	}
	return keys, cas, nil
}

// SetHostKeyPolicy validates and replaces the whole policy (keys and CAs are
// replaced together, never merged). Surrounding whitespace is trimmed from
// each entry. An invalid policy is refused with a fixed error that never
// echoes key text, and the target is left unchanged.
func (t *Target) SetHostKeyPolicy(ctx context.Context, keys, cas []string) error {
	const op = "ssh.(Target).SetHostKeyPolicy"
	keys, cas = trimEntries(keys), trimEntries(cas)
	if err := validateHostKeyPolicy(ctx, keys, cas); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	t.HostKeyPolicyKeys = strings.Join(keys, hostKeySeparator)
	t.HostKeyPolicyCas = strings.Join(cas, hostKeySeparator)
	return nil
}

// SetStoredHostKeyPolicy sets the stored form of the policy as read from the
// database. It does not validate: HostKeyPolicy does, on every read.
func (t *Target) SetStoredHostKeyPolicy(keys, cas string) {
	t.HostKeyPolicyKeys, t.HostKeyPolicyCas = keys, cas
}

// validateHostKeyPolicy checks normalised entries with the same rules the
// worker enforces. Errors are fixed strings and never contain key text.
func validateHostKeyPolicy(ctx context.Context, keys, cas []string) error {
	const op = "ssh.validateHostKeyPolicy"
	invalid := func(msg string) error {
		return errors.New(ctx, errors.InvalidParameter, op, msg)
	}
	for _, list := range [][]string{keys, cas} {
		if len(list) > hostkeypolicy.MaxHostKeys {
			return invalid("too many host key policy entries")
		}
		for _, e := range list {
			// An entry that is not normalised could smuggle in a separator.
			if e != strings.TrimSpace(e) || strings.Contains(e, hostKeySeparator) {
				return invalid("host key policy entry is not normalised")
			}
		}
	}
	if err := hostkeypolicy.ValidateHostKeys(keys); err != nil {
		return invalid("invalid pinned host keys")
	}
	seen := make(map[string]bool, len(cas))
	for _, ca := range cas {
		if err := hostkeypolicy.ValidateHostCA(ca); err != nil {
			return invalid("invalid host ca")
		}
		pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(ca))
		if err != nil {
			return invalid("invalid host ca")
		}
		fp := gossh.FingerprintSHA256(pub)
		if seen[fp] {
			return invalid("duplicate host ca")
		}
		seen[fp] = true
	}
	return nil
}

func splitEntries(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, hostKeySeparator)
}

func trimEntries(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, e := range in {
		out[i] = strings.TrimSpace(e)
	}
	return out
}
