// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package masking

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sess = SessionInfo{TargetID: "ttcp_1", ScopeIDs: []string{"p_1", "o_1", "global"}, RoleIDs: []string{"r_1"}, PrincipalIDs: []string{"u_1"}}

func rule(id string, k DetectorKind, a Selectors) Rule {
	return Rule{ID: id, Detector: k, AppliesTo: a, Enabled: true}
}

func run(t *testing.T, c *Compiled, in string) string {
	t.Helper()
	var buf bytes.Buffer
	r, err := c.NewRedactor(&buf)
	require.NoError(t, err)
	_, err = r.Write([]byte(in))
	require.NoError(t, err)
	require.NoError(t, r.Close())
	return buf.String()
}

func TestSelectors(t *testing.T) {
	tests := []struct {
		name string
		sel  Selectors
		want bool
	}{
		{"empty matches nothing", Selectors{}, false},
		{"empty strings match nothing", Selectors{TargetIDs: []string{""}, ScopeIDs: []string{""}}, false},
		{"all targets", Selectors{AllTargets: true}, true},
		{"target id", Selectors{TargetIDs: []string{"ttcp_1"}}, true},
		{"other target", Selectors{TargetIDs: []string{"ttcp_2"}}, false},
		{"ancestor scope", Selectors{ScopeIDs: []string{"o_1"}}, true},
		{"other scope", Selectors{ScopeIDs: []string{"o_2"}}, false},
		{"role", Selectors{RoleIDs: []string{"r_1"}}, true},
		{"principal", Selectors{PrincipalIDs: []string{"u_1"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.sel.matches(sess))
		})
	}
	// A session with empty ids must not match empty selector entries.
	assert.False(t, Selectors{TargetIDs: []string{""}}.matches(SessionInfo{}))
}

func TestCompileSelection(t *testing.T) {
	disabled := rule("r_dis", KindEmail, Selectors{AllTargets: true})
	disabled.Enabled = false
	c, err := Compile([]Rule{
		rule("r_none", KindEmail, Selectors{}),
		rule("r_other", KindEmail, Selectors{TargetIDs: []string{"ttcp_9"}}),
		disabled,
		rule("r_all", KindCreditCard, Selectors{AllTargets: true}),
	}, sess, Limits{})
	require.NoError(t, err)
	assert.Equal(t, []string{"r_all"}, c.RuleIDs())
	out := run(t, c, "a@example.com 4111 1111 1111 1111")
	assert.Contains(t, out, "a@example.com", "disabled/non-applicable rules must not apply")
	assert.Contains(t, out, "[REDACTED:credit_card]")
}

func TestCompileNoRulesPassesThrough(t *testing.T) {
	c, err := Compile(nil, sess, Limits{})
	require.NoError(t, err)
	assert.Equal(t, 0, c.Len())
	assert.Equal(t, "a@example.com", run(t, c, "a@example.com"))
}

func TestCompileFailsClosed(t *testing.T) {
	all := Selectors{AllTargets: true}
	long := rule("r_long", KindRegex, all)
	long.Regex = strings.Repeat("a", 600)
	bad := rule("r_bad", KindRegex, all)
	bad.Regex = "(secret-pw-123"
	empty := rule("r_empty", KindRegex, all)
	empty.Regex = "a*"
	noRe := rule("r_nore", KindRegex, all)
	extraRe := rule("r_extra", KindEmail, all)
	extraRe.Regex = "x"
	unknown := rule("r_unk", "nope", all)
	noID := rule("", KindEmail, all)
	tests := []struct {
		name  string
		rules []Rule
		lim   Limits
		want  error
	}{
		{"regex too long", []Rule{long}, Limits{}, ErrInvalidRule},
		{"bad regex", []Rule{bad}, Limits{}, ErrInvalidRule},
		{"empty-matching regex", []Rule{empty}, Limits{}, ErrInvalidRule},
		{"regex missing", []Rule{noRe}, Limits{}, ErrInvalidRule},
		{"regex on builtin", []Rule{extraRe}, Limits{}, ErrInvalidRule},
		{"unknown detector", []Rule{unknown}, Limits{}, ErrInvalidRule},
		{"missing id", []Rule{noID}, Limits{}, ErrInvalidRule},
		{"duplicate id", []Rule{rule("a", KindEmail, all), rule("a", KindJWT, all)}, Limits{}, ErrDuplicateRuleID},
		{"too many", []Rule{rule("a", KindEmail, all), rule("b", KindJWT, all)}, Limits{MaxRules: 1}, ErrTooManyRules},
		{"negative limit", nil, Limits{MaxRules: -1}, ErrInvalidLimits},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Compile(tt.rules, sess, tt.lim)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.want), err.Error())
			assert.Nil(t, c)
			assert.NotContains(t, err.Error(), "secret-pw-123", "errors must not echo patterns")
		})
	}
}

func TestInvalidDisabledOrInapplicableRuleIsIgnored(t *testing.T) {
	bad := rule("r_bad", KindRegex, Selectors{TargetIDs: []string{"ttcp_9"}})
	bad.Regex = "("
	dis := rule("r_dis", KindRegex, Selectors{AllTargets: true})
	dis.Regex = "("
	dis.Enabled = false
	_, err := Compile([]Rule{bad, dis}, sess, Limits{})
	require.NoError(t, err)
}

func TestReplacement(t *testing.T) {
	for _, rep := range []string{"$0", "${1}", "\\1", "{detector}", "a\nb", strings.Repeat("x", 129)} {
		r := rule("r", KindEmail, Selectors{AllTargets: true})
		r.Replacement = rep
		c, err := Compile([]Rule{r}, sess, Limits{})
		assert.ErrorIs(t, err, ErrInvalidRule, "%q", rep)
		assert.Nil(t, c)
	}
	r := rule("r", KindEmail, Selectors{AllTargets: true})
	r.Replacement = "<hidden>"
	c, err := Compile([]Rule{r}, sess, Limits{})
	require.NoError(t, err)
	assert.Equal(t, "x <hidden> y", run(t, c, "x a@example.com y"))
}

func TestCustomRegexAndOverlapMergesToWidest(t *testing.T) {
	all := Selectors{AllTargets: true}
	short := rule("short", KindRegex, all)
	short.Regex = `token-[0-9]+`
	short.Replacement = "[SHORT]"
	wide := rule("wide", KindRegex, all)
	wide.Regex = `id=token-[0-9]+;`
	wide.Replacement = "[WIDE]"
	c, err := Compile([]Rule{short, wide}, sess, Limits{})
	require.NoError(t, err)
	assert.Equal(t, "x [WIDE] y", run(t, c, "x id=token-123; y"))
	assert.Equal(t, "[SHORT]", run(t, c, "token-9"))
}

func TestPrivateKeyRuleKeepsPartialHoldBack(t *testing.T) {
	c, err := Compile([]Rule{rule("pk", KindPrivateKey, Selectors{AllTargets: true})}, sess, Limits{})
	require.NoError(t, err)
	var buf bytes.Buffer
	r, err := c.NewRedactor(&buf)
	require.NoError(t, err)
	for _, part := range []string{"-----BEGIN PRIVATE KEY-----\nAAAA\n", "BBBB\n-----END PRIVATE KEY-----\ndone"} {
		_, err = r.Write([]byte(part))
		require.NoError(t, err)
	}
	require.NoError(t, r.Close())
	assert.NotContains(t, buf.String(), "AAAA")
	assert.NotContains(t, buf.String(), "BBBB")
	assert.Contains(t, buf.String(), "[REDACTED:private_key]")
}

func TestRuleIDsIsACopy(t *testing.T) {
	c, err := Compile([]Rule{rule("a", KindEmail, Selectors{AllTargets: true})}, sess, Limits{})
	require.NoError(t, err)
	c.RuleIDs()[0] = "zzz"
	assert.Equal(t, []string{"a"}, c.RuleIDs())
}
