// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package guardrails

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func okRule(id string) Rule {
	return Rule{
		ID: id, Name: id, ScopeID: "o_1",
		Match:     Match{Kind: MatchPrefix, Pattern: "rm -rf"},
		Action:    ActionDeny,
		Selectors: Selectors{TargetIDs: []string{"tssh_1"}},
		Message:   "blocked",
		Enabled:   true,
	}
}

var sess = SessionInfo{TargetID: "tssh_1", ScopeIDs: []string{"p_1", "o_1"}, RoleIDs: []string{"r_1"}, PrincipalIDs: []string{"u_1"}}

func TestCompileFailures(t *testing.T) {
	mut := func(f func(*Rule)) []Rule { r := okRule("a"); f(&r); return []Rule{r} }
	tests := []struct {
		name   string
		rules  []Rule
		limits Limits
		want   error
	}{
		{"empty id", mut(func(r *Rule) { r.ID = "" }), Limits{}, ErrInvalidRule},
		{"dup id", []Rule{okRule("a"), okRule("a")}, Limits{}, ErrDuplicateRuleID},
		{"dup id disabled", []Rule{okRule("a"), func() Rule { r := okRule("a"); r.Enabled = false; return r }()}, Limits{}, ErrDuplicateRuleID},
		{"bad regexp", mut(func(r *Rule) { r.Match = Match{MatchRegexp, "(unclosed"} }), Limits{}, ErrInvalidRule},
		{"backreference (not RE2)", mut(func(r *Rule) { r.Match = Match{MatchRegexp, `(a)\1`} }), Limits{}, ErrInvalidRule},
		{"empty-matching regexp", mut(func(r *Rule) { r.Match = Match{MatchRegexp, "a*"} }), Limits{}, ErrInvalidRule},
		{"empty pattern", mut(func(r *Rule) { r.Match.Pattern = "" }), Limits{}, ErrInvalidRule},
		{"blank prefix", mut(func(r *Rule) { r.Match.Pattern = "  " }), Limits{}, ErrInvalidRule},
		{"invalid utf8", mut(func(r *Rule) { r.Match.Pattern = "\xff" }), Limits{}, ErrInvalidRule},
		{"unknown kind", mut(func(r *Rule) { r.Match.Kind = "glob" }), Limits{}, ErrInvalidRule},
		{"unknown action", mut(func(r *Rule) { r.Action = "allow" }), Limits{}, ErrInvalidRule},
		{"empty action", mut(func(r *Rule) { r.Action = "" }), Limits{}, ErrInvalidRule},
		{"pattern too long", mut(func(r *Rule) { r.Match.Pattern = strings.Repeat("a", 11) }), Limits{MaxPatternLen: 10}, ErrInvalidRule},
		{"message too long", mut(func(r *Rule) { r.Message = strings.Repeat("a", 11) }), Limits{MaxMessageLen: 10}, ErrInvalidRule},
		{"message placeholder", mut(func(r *Rule) { r.Message = "no ${cmd}" }), Limits{}, ErrInvalidRule},
		{"message control char", mut(func(r *Rule) { r.Message = "a\nb" }), Limits{}, ErrInvalidRule},
		{"review unsupported", mut(func(r *Rule) { r.Action = ActionRequireReview }), Limits{}, ErrInvalidRule},
		{"invalid rule not applicable still fails", mut(func(r *Rule) { r.Selectors = Selectors{TargetIDs: []string{"other"}}; r.Action = "x" }), Limits{}, ErrInvalidRule},
		{"id too long", mut(func(r *Rule) { r.ID = strings.Repeat("a", MaxRuleIDLen+1) }), Limits{}, ErrInvalidRule},
		{"id invalid utf8", mut(func(r *Rule) { r.ID = "\xff" }), Limits{}, ErrInvalidRule},
		{"message C1 control", mut(func(r *Rule) { r.Message = "a\u0085b" }), Limits{}, ErrInvalidRule},
		{"message bidi override", mut(func(r *Rule) { r.Message = "a\u202eb" }), Limits{}, ErrInvalidRule},
		{"too many rules", []Rule{okRule("a"), okRule("b")}, Limits{MaxRules: 1}, ErrTooManyRules},
		{"negative limit", []Rule{okRule("a")}, Limits{MaxRules: -1}, ErrInvalidLimits},
		{"rules above hard max", nil, Limits{MaxRules: HardMaxRules + 1}, ErrInvalidLimits},
		{"pattern above hard max", nil, Limits{MaxPatternLen: HardMaxPatternLen + 1}, ErrInvalidLimits},
		{"message above hard max", nil, Limits{MaxMessageLen: HardMaxMessageLen + 1}, ErrInvalidLimits},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Compile(tt.rules, sess, tt.limits)
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, c)
		})
	}
}

func TestCompileErrorDoesNotEchoPattern(t *testing.T) {
	r := okRule("a")
	r.Match = Match{MatchRegexp, "(secretpattern"}
	_, err := Compile([]Rule{r}, sess, Limits{})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secretpattern")
}

func TestCompileSelection(t *testing.T) {
	with := func(id string, s Selectors, enabled bool) Rule {
		r := okRule(id)
		r.Selectors = s
		r.Enabled = enabled
		return r
	}
	rules := []Rule{
		with("empty", Selectors{}, true),
		with("all", Selectors{AllTargets: true}, true),
		with("target", Selectors{TargetIDs: []string{"tssh_1"}}, true),
		with("othertarget", Selectors{TargetIDs: []string{"tssh_9"}}, true),
		with("scope", Selectors{ScopeIDs: []string{"p_1"}}, true),
		with("role", Selectors{RoleIDs: []string{"r_1"}}, true),
		with("principal", Selectors{PrincipalIDs: []string{"u_1"}}, true),
		with("disabled", Selectors{AllTargets: true}, false),
		with("blankselector", Selectors{TargetIDs: []string{""}}, true),
	}
	c, err := Compile(rules, sess, Limits{})
	require.NoError(t, err)
	assert.Equal(t, []string{"all", "target", "scope", "role", "principal"}, c.RuleIDs())
	assert.Equal(t, 5, c.Len())

	// A session with no identity matches only the explicit all-targets rule.
	c, err = Compile(rules, SessionInfo{}, Limits{})
	require.NoError(t, err)
	assert.Equal(t, []string{"all"}, c.RuleIDs())
}

func TestCompileReviewSupported(t *testing.T) {
	r := okRule("a")
	r.Action = ActionRequireReview
	c, err := Compile([]Rule{r}, sess, Limits{ReviewsSupported: true})
	require.NoError(t, err)
	assert.Equal(t, 1, c.Len())

	// Not applicable to the session: no error even if unsupported.
	r.Selectors = Selectors{TargetIDs: []string{"other"}}
	c, err = Compile([]Rule{r}, sess, Limits{})
	require.NoError(t, err)
	assert.Equal(t, 0, c.Len())
}

func TestCompileResultIsCopy(t *testing.T) {
	c, err := Compile([]Rule{okRule("a")}, sess, Limits{})
	require.NoError(t, err)
	c.RuleIDs()[0] = "changed"
	assert.Equal(t, []string{"a"}, c.RuleIDs())
}

func TestNilAndEmpty(t *testing.T) {
	assert.NotPanics(t, func() {
		var c *Compiled
		assert.Nil(t, c.RuleIDs())
		assert.Equal(t, 0, c.Len())
		assert.Equal(t, "", c.RuleSetHash())
		c, err := Compile(nil, SessionInfo{}, Limits{})
		require.NoError(t, err)
		assert.Equal(t, 0, c.Len())
		assert.Len(t, c.RuleSetHash(), 64)
		c, err = Compile([]Rule{}, SessionInfo{}, DefaultLimits())
		require.NoError(t, err)
		assert.Equal(t, 0, c.Len())
	})
}

func TestRuleSetHash(t *testing.T) {
	a, b := okRule("a"), okRule("b")
	b.Match = Match{MatchRegexp, `DROP\s+TABLE`}
	a.Selectors.TargetIDs = []string{"tssh_1", "tssh_2"}

	h := func(rules ...Rule) string {
		c, err := Compile(rules, sess, Limits{})
		require.NoError(t, err)
		return c.RuleSetHash()
	}
	base := h(a, b)
	assert.Equal(t, base, h(a, b))
	assert.Equal(t, base, h(b, a), "order independent")
	a2 := a
	a2.Selectors.TargetIDs = []string{"tssh_2", "tssh_1"}
	assert.Equal(t, base, h(a2, b), "selector order independent")
	assert.NotEqual(t, base, h(a))

	changes := map[string]func(*Rule){
		"id":      func(r *Rule) { r.ID = "z" },
		"scope":   func(r *Rule) { r.ScopeID = "o_2" },
		"kind":    func(r *Rule) { r.Match.Kind = MatchRegexp },
		"pattern": func(r *Rule) { r.Match.Pattern = "rm -r" },
		"action":  func(r *Rule) { r.Action = ActionRequireReview },
		"message": func(r *Rule) { r.Message = "nope" },
		"target":  func(r *Rule) { r.Selectors.TargetIDs = []string{"tssh_1"} },
		"scopes":  func(r *Rule) { r.Selectors.ScopeIDs = []string{"p_1"} },
		"roles":   func(r *Rule) { r.Selectors.RoleIDs = []string{"r_1"} },
		"princs":  func(r *Rule) { r.Selectors.PrincipalIDs = []string{"u_1"} },
		"all":     func(r *Rule) { r.Selectors.AllTargets = true },
	}
	for name, f := range changes {
		t.Run(name, func(t *testing.T) {
			m := a
			f(&m)
			c, err := Compile([]Rule{m, b}, sess, Limits{ReviewsSupported: true})
			require.NoError(t, err)
			c0, err := Compile([]Rule{a, b}, sess, Limits{ReviewsSupported: true})
			require.NoError(t, err)
			assert.NotEqual(t, c0.RuleSetHash(), c.RuleSetHash())
		})
	}

	// Rules that do not apply or are disabled do not affect the hash.
	other := okRule("other")
	other.Selectors = Selectors{TargetIDs: []string{"zzz"}}
	off := okRule("off")
	off.Enabled = false
	assert.Equal(t, base, h(a, b, other, off))
}

func TestLimitBoundaries(t *testing.T) {
	// Zero Limits apply the documented defaults.
	r := okRule("a")
	r.Match.Pattern = strings.Repeat("a", DefaultMaxPatternLen)
	r.Message = strings.Repeat("m", DefaultMaxMessageLen)
	_, err := Compile([]Rule{r}, sess, Limits{})
	require.NoError(t, err)
	r.Match.Pattern += "a"
	_, err = Compile([]Rule{r}, sess, Limits{})
	require.ErrorIs(t, err, ErrInvalidRule)
	r = okRule("a")
	r.Message = strings.Repeat("m", DefaultMaxMessageLen+1)
	_, err = Compile([]Rule{r}, sess, Limits{})
	require.ErrorIs(t, err, ErrInvalidRule)

	// Exactly DefaultMaxRules applicable rules is accepted; one more is not.
	var rules []Rule
	for i := 0; i < DefaultMaxRules; i++ {
		rules = append(rules, okRule(fmt.Sprintf("r%d", i)))
	}
	c, err := Compile(rules, sess, Limits{})
	require.NoError(t, err)
	assert.Equal(t, DefaultMaxRules, c.Len())
	_, err = Compile(append(rules, okRule("extra")), sess, Limits{})
	require.ErrorIs(t, err, ErrTooManyRules)

	// Hard maxima themselves are accepted.
	_, err = Compile(nil, sess, Limits{MaxRules: HardMaxRules, MaxPatternLen: HardMaxPatternLen, MaxMessageLen: HardMaxMessageLen})
	require.NoError(t, err)

	// A huge input list is rejected before any rule is examined.
	_, err = Compile(make([]Rule, MaxInputRules+1), sess, Limits{})
	require.ErrorIs(t, err, ErrTooManyRules)
}
