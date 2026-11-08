// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package masking

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pr(id string, k DetectorKind, o Origin) PolicyRule {
	return PolicyRule{Rule: rule(id, k, Selectors{AllTargets: true}), Origin: o}
}

func redact(t *testing.T, p *Policy, in string) string {
	t.Helper()
	var buf bytes.Buffer
	r, err := p.NewRedactor(&buf)
	require.NoError(t, err)
	_, err = r.Write([]byte(in))
	require.NoError(t, err)
	require.NoError(t, r.Close())
	return buf.String()
}

func TestRecordingEnabledAlwaysHasBuiltins(t *testing.T) {
	off := pr("c1", KindEmail, OriginChild)
	off.Rule.Enabled = false
	p, err := EffectivePolicy(PolicyInput{RecordingEnabled: true, Rules: []PolicyRule{off}, Session: sess})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"builtin:credit_card", "builtin:aws_access_key", "builtin:jwt", "builtin:private_key"}, p.RuleIDs())
	out := redact(t, p, "key AKIAIOSFODNN7EXAMPLE card 4111 1111 1111 1111 mail a@example.com")
	assert.NotContains(t, out, "AKIAIOSFODNN7EXAMPLE")
	assert.NotContains(t, out, "4111")
	assert.Contains(t, out, "a@example.com", "email is optional")

	p, err = EffectivePolicy(PolicyInput{RecordingEnabled: true, IncludeEmail: true, Session: sess})
	require.NoError(t, err)
	assert.Contains(t, p.RuleIDs(), "builtin:email")
}

func TestChildCannotDisableOrOverrideParent(t *testing.T) {
	parent := pr("p1", KindEmail, OriginParent)
	in := PolicyInput{Rules: []PolicyRule{parent}, ChildDisabled: []string{"p1", "builtin:jwt"}, Session: sess}
	p, err := EffectivePolicy(in)
	require.NoError(t, err)
	assert.Equal(t, []string{"p1"}, p.RuleIDs())
	assert.Equal(t, 2, p.IgnoredOverrides())

	in.RecordingEnabled = true
	p, err = EffectivePolicy(in)
	require.NoError(t, err)
	assert.Contains(t, p.RuleIDs(), "builtin:jwt")
	assert.Contains(t, p.RuleIDs(), "p1")
	assert.Equal(t, 2, p.IgnoredOverrides())

	// A child rule reusing a parent id (replace/narrow) is rejected.
	child := pr("p1", KindEmail, OriginChild)
	child.Rule.AppliesTo = Selectors{TargetIDs: []string{"other"}}
	_, err = EffectivePolicy(PolicyInput{Rules: []PolicyRule{parent, child}, Session: sess})
	require.ErrorIs(t, err, ErrParentRuleOverride)

	// A child may disable and add its own rules.
	c1 := pr("c1", KindEmail, OriginChild)
	p, err = EffectivePolicy(PolicyInput{Rules: []PolicyRule{parent, c1}, ChildDisabled: []string{"c1"}, Session: sess})
	require.NoError(t, err)
	assert.Equal(t, []string{"p1"}, p.RuleIDs())
}

func TestDuplicateRuleIDsRejected(t *testing.T) {
	for _, o := range []Origin{OriginParent, OriginChild} {
		_, err := EffectivePolicy(PolicyInput{Rules: []PolicyRule{pr("d", KindEmail, o), pr("d", KindJWT, o)}, Session: sess})
		require.ErrorIs(t, err, ErrDuplicateRuleID)
	}
}

func TestUnsetOriginIsParent(t *testing.T) {
	var r PolicyRule
	r.Rule = rule("x", KindEmail, Selectors{AllTargets: true})
	p, err := EffectivePolicy(PolicyInput{Rules: []PolicyRule{r}, ChildDisabled: []string{"x"}, Session: sess})
	require.NoError(t, err)
	assert.Equal(t, []string{"x"}, p.RuleIDs())
}

func TestReservedAndUnknownOrigin(t *testing.T) {
	_, err := EffectivePolicy(PolicyInput{Rules: []PolicyRule{pr("builtin:jwt", KindJWT, OriginChild)}, Session: sess})
	require.ErrorIs(t, err, ErrReservedRuleID)
	_, err = EffectivePolicy(PolicyInput{Rules: []PolicyRule{pr("a", KindJWT, Origin(9))}, Session: sess})
	require.ErrorIs(t, err, ErrInvalidRule)
}

func TestEmptyPolicyNeedsExplicitAllow(t *testing.T) {
	_, err := EffectivePolicy(PolicyInput{Session: sess})
	require.ErrorIs(t, err, ErrEmptyPolicy)

	p, err := EffectivePolicy(PolicyInput{AllowNoop: true, Session: sess})
	require.NoError(t, err)
	assert.Equal(t, 0, p.Len())
	assert.Equal(t, "plain", redact(t, p, "plain"))

	// AllowNoop does not weaken a recording-enabled target.
	p, err = EffectivePolicy(PolicyInput{AllowNoop: true, RecordingEnabled: true, Session: sess})
	require.NoError(t, err)
	assert.Equal(t, 4, p.Len())
}

func TestFailsClosedOnInvalid(t *testing.T) {
	bad := pr("r", KindRegex, OriginChild) // regex required
	p, err := EffectivePolicy(PolicyInput{RecordingEnabled: true, Rules: []PolicyRule{bad}, Session: sess})
	require.ErrorIs(t, err, ErrInvalidRule)
	assert.Nil(t, p)
	_, err = EffectivePolicy(PolicyInput{RecordingEnabled: true, Session: sess, Limits: Limits{MaxRules: -1}})
	require.ErrorIs(t, err, ErrInvalidLimits)
	// Too small a rule limit cannot silently drop built-ins.
	_, err = EffectivePolicy(PolicyInput{RecordingEnabled: true, Session: sess, Limits: Limits{MaxRules: 2}})
	require.ErrorIs(t, err, ErrTooManyRules)
}

func TestRuleSetHash(t *testing.T) {
	base := func() PolicyInput {
		r := pr("a", KindRegex, OriginChild)
		r.Rule.Regex = "secret-[0-9]+"
		r.Rule.Replacement = "X"
		return PolicyInput{RecordingEnabled: true, Rules: []PolicyRule{r, pr("b", KindEmail, OriginParent)}, Session: sess}
	}
	h := func(in PolicyInput) string {
		p, err := EffectivePolicy(in)
		require.NoError(t, err)
		require.Len(t, p.RuleSetHash(), 64)
		return p.RuleSetHash()
	}
	want := h(base())
	assert.Equal(t, want, h(base()), "same rules, same hash")

	reordered := base()
	reordered.Rules[0], reordered.Rules[1] = reordered.Rules[1], reordered.Rules[0]
	assert.Equal(t, want, h(reordered), "order does not matter")

	changes := map[string]func(*PolicyInput){
		"regex":       func(in *PolicyInput) { in.Rules[0].Rule.Regex = "secret-[0-8]+" },
		"replacement": func(in *PolicyInput) { in.Rules[0].Rule.Replacement = "Y" },
		"selector": func(in *PolicyInput) {
			in.Rules[1].Rule.AppliesTo = Selectors{AllTargets: true, RoleIDs: []string{"r_1"}}
		},
		"disabled": func(in *PolicyInput) { in.Rules[1].Rule.Enabled = false },
		"email":    func(in *PolicyInput) { in.IncludeEmail = true },
		"id":       func(in *PolicyInput) { in.Rules[1].Rule.ID = "c" },
	}
	for name, f := range changes {
		in := base()
		f(&in)
		assert.NotEqual(t, want, h(in), name)
	}
}
