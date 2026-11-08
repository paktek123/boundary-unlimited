// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package approval_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/runbook"
	"github.com/hashicorp/boundary/internal/runbook/approval"
	"github.com/hashicorp/boundary/internal/runbook/source"
	"github.com/stretchr/testify/require"
)

const sha1 = "0123456789abcdef0123456789abcdef01234567"
const sha2 = "fedcba9876543210fedcba9876543210fedcba98"

func def(script string, names ...string) runbook.Definition {
	d := runbook.Definition{Name: "restart-svc", Script: []byte(script)}
	for _, n := range names {
		d.Parameters = append(d.Parameters, runbook.Parameter{Name: n, Type: runbook.TypeString})
	}
	return d
}

func bind(t *testing.T, sha string, d runbook.Definition) approval.Binding {
	t.Helper()
	pin, err := source.NewPin(sha, d.Script)
	require.NoError(t, err)
	b, err := approval.Bind(d, pin)
	require.NoError(t, err)
	return b
}

func TestVerify(t *testing.T) {
	base := bind(t, sha1, def("echo hi", "b", "a"))
	tests := []struct {
		name string
		cur  approval.Binding
		want error
	}{
		{"same", bind(t, sha1, def("echo hi", "a", "b")), nil},
		{"different sha", bind(t, sha2, def("echo hi", "a", "b")), approval.ErrMismatch},
		{"different script", bind(t, sha1, def("echo bye", "a", "b")), approval.ErrMismatch},
		{"param added", bind(t, sha1, def("echo hi", "a", "b", "c")), approval.ErrMismatch},
		{"param removed", bind(t, sha1, def("echo hi", "a")), approval.ErrMismatch},
		{"param renamed", bind(t, sha1, def("echo hi", "a", "z")), approval.ErrMismatch},
		{"different runbook", func() approval.Binding { b := base; b.RunbookRef = "other"; return b }(), approval.ErrMismatch},
		{"zero current", approval.Binding{}, approval.ErrEmptyBinding},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := approval.Verify(base, tc.cur)
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
		})
	}
	require.ErrorIs(t, approval.Verify(approval.Binding{}, base), approval.ErrEmptyBinding)
	require.ErrorIs(t, approval.Verify(approval.Binding{}, approval.Binding{}), approval.ErrEmptyBinding)
}

func TestVerifyUnsortedNamesDoNotBypass(t *testing.T) {
	base := bind(t, sha1, def("x", "a", "b"))
	cur := base
	cur.ParamNames = []string{"b", "a"} // same set, different order: still the same set
	require.NoError(t, approval.Verify(base, cur))
	cur.ParamNames = []string{"a", "a"}
	require.Error(t, approval.Verify(base, cur))
}

func TestVerifyRejectsDuplicateNamesOnBothSides(t *testing.T) {
	d := bind(t, sha1, def("x", "a", "b"))
	d.ParamNames = []string{"a", "a"}
	require.ErrorIs(t, approval.Verify(d, d), approval.ErrEmptyBinding)
}

func TestBindFailsClosed(t *testing.T) {
	d := def("x", "a")
	pin, err := source.NewPin(sha1, d.Script)
	require.NoError(t, err)
	_, err = approval.Bind(runbook.Definition{Script: d.Script}, pin)
	require.ErrorIs(t, err, approval.ErrEmptyBinding)
	_, err = approval.Bind(d, source.Pin{})
	require.ErrorIs(t, err, approval.ErrEmptyBinding)
	_, err = approval.Bind(def("tampered", "a"), pin)
	require.ErrorIs(t, err, approval.ErrMismatch)
	_, err = approval.Bind(def("x", "a", "a"), pin)
	require.ErrorIs(t, err, approval.ErrDuplicateParam)
	_, err = approval.Bind(def("x", ""), pin)
	require.ErrorIs(t, err, approval.ErrEmptyBinding)
}

func TestCanonicalGolden(t *testing.T) {
	b := bind(t, sha1, def("echo hi", "zeta", "alpha"))
	want := "runbook-approval-binding/v1\n" +
		"11:restart-svc\n" +
		"40:" + sha1 + "\n" +
		"64:" + b.ScriptHash + "\n" +
		"params:2\n" +
		"5:alpha\n" +
		"4:zeta\n"
	require.Equal(t, want, b.Canonical())
	// Deterministic.
	require.Equal(t, b.Canonical(), bind(t, sha1, def("echo hi", "alpha", "zeta")).Canonical())
}

func TestValuesNeverAppear(t *testing.T) {
	const canary = "CANARY-VALUE-9f8e7d"
	d := def("echo hi", "p")
	d.Parameters[0].Default = canary
	d.Parameters[0].HasDefault = true
	b := bind(t, sha1, d)
	out := []string{b.Canonical(), b.String(), fmt.Sprintf("%v %+v %#v", b, b, b)}
	cur := bind(t, sha2, d)
	err := approval.Verify(b, cur)
	require.Error(t, err)
	out = append(out, err.Error())
	for _, o := range out {
		require.False(t, strings.Contains(o, canary), "value leaked: %s", o)
	}
}
