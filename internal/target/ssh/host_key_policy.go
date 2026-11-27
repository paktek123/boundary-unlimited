// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target/ssh/hostkeypolicy"
	"github.com/lib/pq"
)

// HostKeyPolicy returns the pinned host keys and host CAs stored on the
// target, in authorized_keys format. The policy lives on the target only:
// there is no other source and no trust on first use. Nothing accepts the
// policy through the API yet.
func (t *Target) HostKeyPolicy(ctx context.Context) (keys, cas []string, err error) {
	const op = "ssh.(Target).HostKeyPolicy"
	keys, err = decodeTextArray(t.GetHostKeyPolicyKeys())
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("stored host key policy keys are unreadable"))
	}
	cas, err = decodeTextArray(t.GetHostKeyPolicyCas())
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("stored host key policy cas are unreadable"))
	}
	return keys, cas, nil
}

// SetHostKeyPolicy validates and replaces the whole policy (keys and CAs are
// replaced together, never merged). An invalid policy is refused with a fixed
// error that never echoes key text, and the target is left unchanged.
func (t *Target) SetHostKeyPolicy(ctx context.Context, keys, cas []string) error {
	const op = "ssh.(Target).SetHostKeyPolicy"
	if err := validateHostKeyPolicy(ctx, keys, cas); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	k, err := encodeTextArray(keys)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	c, err := encodeTextArray(cas)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	t.Target.HostKeyPolicyKeys, t.Target.HostKeyPolicyCas = k, c
	return nil
}

// validateHostKeyPolicy checks the policy with the same rules the worker
// enforces. Errors are fixed strings and never contain key text.
func validateHostKeyPolicy(ctx context.Context, keys, cas []string) error {
	const op = "ssh.validateHostKeyPolicy"
	if err := hostkeypolicy.ValidateHostKeys(keys); err != nil {
		return errors.New(ctx, errors.InvalidParameter, op, "invalid pinned host keys")
	}
	if len(cas) > hostkeypolicy.MaxHostKeys {
		return errors.New(ctx, errors.InvalidParameter, op, "too many host cas")
	}
	for _, ca := range cas {
		if err := hostkeypolicy.ValidateHostCA(ca); err != nil {
			return errors.New(ctx, errors.InvalidParameter, op, "invalid host ca")
		}
	}
	return nil
}

// vetStoredHostKeyPolicy validates the policy carried by the target before a
// write, so a value that did not go through SetHostKeyPolicy is still refused.
func (t *Target) vetStoredHostKeyPolicy(ctx context.Context) error {
	keys, cas, err := t.HostKeyPolicy(ctx)
	if err != nil {
		return err
	}
	return validateHostKeyPolicy(ctx, keys, cas)
}

func encodeTextArray(v []string) (string, error) {
	if len(v) == 0 {
		return "{}", nil
	}
	out, err := pq.StringArray(v).Value()
	if err != nil {
		return "", err
	}
	return out.(string), nil
}

func decodeTextArray(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	var a pq.StringArray
	if err := a.Scan(s); err != nil {
		return nil, err
	}
	if len(a) == 0 {
		return nil, nil
	}
	return []string(a), nil
}
