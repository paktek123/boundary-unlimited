// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package guardrails

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func compileRules(t *testing.T, rules ...Rule) *Compiled {
	t.Helper()
	c, err := Compile(rules, sess, Limits{ReviewsSupported: true})
	require.NoError(t, err)
	return c
}

func rule(id string, kind MatchKind, pattern string, action Action) Rule {
	r := okRule(id)
	r.Match = Match{Kind: kind, Pattern: pattern}
	r.Action = action
	return r
}

func TestNormalise(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain", "ls -la", "ls -la", false},
		{"tab and newline", "a\tb\nc", "a\tb\nc", false},
		{"fullwidth folds", "ｒｍ －ｒｆ /", "rm -rf /", false},
		{"invalid utf8", "ls \xff", "", true},
		{"nul", "ls\x00", "", true},
		{"carriage return", "ls\r", "", true},
		{"escape", "ls\x1b[0m", "", true},
		{"del", "ls\x7f", "", true},
		{"c1 control", "ls\u0085", "", true},
		{"bidi override", "ls ‮", "", true},
		{"bidi isolate", "ls ⁦", "", true},
		{"zero width space", "r​m", "", true},
		{"bom", "\ufeffls", "", true},
		{"over length", strings.Repeat("a", MaxCommandLen+1), "", true},
		{"at max length", strings.Repeat("a", MaxCommandLen), strings.Repeat("a", MaxCommandLen), false},
		{"expands past max after NFKC", strings.Repeat("ﷺ", MaxCommandLen/3), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Normalise([]byte(tt.in), 0)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrInvalidCommand)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
	t.Run("maxLen cannot be raised", func(t *testing.T) {
		_, err := Normalise([]byte(strings.Repeat("a", MaxCommandLen+1)), 1<<30)
		require.ErrorIs(t, err, ErrInvalidCommand)
	})
	t.Run("smaller maxLen honoured", func(t *testing.T) {
		_, err := Normalise([]byte("abcd"), 3)
		require.ErrorIs(t, err, ErrInvalidCommand)
	})
}

func TestEvaluate(t *testing.T) {
	c := compileRules(t,
		rule("deny-rm", MatchPrefix, "rm -rf", ActionDeny),
		rule("rev-drop", MatchRegexp, `(?i)drop\s+table`, ActionRequireReview),
		rule("deny-drop", MatchRegexp, `drop table prod`, ActionDeny),
	)
	tests := []struct {
		name string
		in   string
		want Verdict
		rule string
	}{
		{"allowed", "ls -la", VerdictAllow, ""},
		{"prefix deny", "rm -rf /", VerdictBlock, "deny-rm"},
		{"prefix at word boundary only", "rm -rfx /", VerdictAllow, ""},
		{"prefix exact", "rm -rf", VerdictBlock, "deny-rm"},
		{"fullwidth variant blocked", "ｒｍ -ｒｆ /", VerdictBlock, "deny-rm"},
		{"review", "DROP TABLE users", VerdictReview, "rev-drop"},
		{"deny beats review", "drop table prod", VerdictBlock, "deny-drop"},
		{"invalid utf8", "ls \xff", VerdictBlock, ""},
		{"nul", "ls\x00", VerdictBlock, ""},
		{"zero width evasion", "rm​ -rf /", VerdictBlock, ""},
		{"too long", strings.Repeat("a", MaxCommandLen+1), VerdictBlock, ""},
		{"empty command", "", VerdictAllow, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := c.Evaluate([]byte(tt.in))
			assert.Equal(t, tt.want, d.Verdict)
			assert.Equal(t, tt.rule, d.RuleID)
			assert.Equal(t, c.RuleSetHash(), d.RuleSetHash)
		})
	}
}

func TestEvaluateRawAndNormalisedIndependently(t *testing.T) {
	// A pattern that only the fullwidth raw form matches: the normalised form
	// is ASCII, so only the raw match can fire.
	rawOnly := compileRules(t, rule("raw", MatchRegexp, `ｒｍ`, ActionDeny))
	assert.Equal(t, VerdictBlock, rawOnly.Evaluate([]byte("ｒｍ x")).Verdict)
	// Only the normalised form matches.
	normOnly := compileRules(t, rule("norm", MatchRegexp, `^rm x`, ActionDeny))
	assert.Equal(t, VerdictBlock, normOnly.Evaluate([]byte("ｒｍ x")).Verdict)
	assert.Equal(t, VerdictAllow, normOnly.Evaluate([]byte("ls")).Verdict)
}

func TestEvaluateNilAndEmptySets(t *testing.T) {
	var nilSet *Compiled
	assert.Equal(t, VerdictBlock, nilSet.Evaluate([]byte("ls")).Verdict)
	empty, err := Compile(nil, sess, Limits{})
	require.NoError(t, err)
	assert.Equal(t, VerdictAllow, empty.Evaluate([]byte("ls")).Verdict)
}

func TestEvaluatePanicBlocksWithoutLeak(t *testing.T) {
	const canary = "CANARY-secret-command-9f3a"
	c := compileRules(t, rule("a", MatchPrefix, "zzz", ActionDeny))
	c.matchers = append(c.matchers, matcher{id: "boom", action: ActionDeny, match: func(s string) bool { panic(s) }})
	d := c.Evaluate([]byte("echo " + canary))
	assert.Equal(t, VerdictBlock, d.Verdict)
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", d, d, d), canary)
}

func TestDecisionNeverHoldsCommand(t *testing.T) {
	const canary = "CANARY-secret-command-77c1"
	c := compileRules(t, rule("d", MatchRegexp, `CANARY`, ActionDeny))
	for _, in := range []string{"echo " + canary, "ok " + canary + "\xff", "ls"} {
		d := c.Evaluate([]byte(in))
		assert.NotContains(t, fmt.Sprintf("%v %+v %#v", d, d, d), canary)
	}
	_, err := Normalise([]byte("x\x00"+canary), 0)
	assert.NotContains(t, err.Error(), canary)
}

func TestWithAllowList(t *testing.T) {
	base := compileRules(t, rule("deny-rm", MatchPrefix, "rm", ActionDeny))
	al, err := base.WithAllowList([]string{`^ls( |$)`, `^rm -i `})
	require.NoError(t, err)

	assert.Equal(t, VerdictAllow, al.Evaluate([]byte("ls -la")).Verdict)
	d := al.Evaluate([]byte("whoami"))
	assert.Equal(t, VerdictBlock, d.Verdict, "unlisted command blocked")
	assert.Empty(t, d.RuleID)
	assert.Equal(t, VerdictBlock, al.Evaluate([]byte("rm -i foo")).Verdict, "deny beats allow")
	assert.Equal(t, "deny-rm", al.Evaluate([]byte("rm -i foo")).RuleID)
	// Fullwidth "ls": the raw form does not match the allow list.
	assert.Equal(t, VerdictBlock, al.Evaluate([]byte("ｌｓ")).Verdict, "raw form must also match")

	// The base set is unchanged.
	assert.Equal(t, VerdictAllow, base.Evaluate([]byte("whoami")).Verdict)

	t.Run("empty list blocks everything", func(t *testing.T) {
		none, err := base.WithAllowList(nil)
		require.NoError(t, err)
		assert.Equal(t, VerdictBlock, none.Evaluate([]byte("ls")).Verdict)
	})
	t.Run("hash covers patterns", func(t *testing.T) {
		a, _ := base.WithAllowList([]string{`^ls`})
		b, _ := base.WithAllowList([]string{`^ls `})
		none, _ := base.WithAllowList(nil)
		assert.NotEqual(t, base.RuleSetHash(), a.RuleSetHash())
		assert.NotEqual(t, a.RuleSetHash(), b.RuleSetHash())
		assert.NotEqual(t, a.RuleSetHash(), none.RuleSetHash())
		a2, _ := base.WithAllowList([]string{`^ls`})
		assert.Equal(t, a.RuleSetHash(), a2.RuleSetHash())
		order1, _ := base.WithAllowList([]string{"^a", "^b"})
		order2, _ := base.WithAllowList([]string{"^b", "^a"})
		assert.Equal(t, order1.RuleSetHash(), order2.RuleSetHash())
	})
	t.Run("invalid patterns", func(t *testing.T) {
		for name, p := range map[string][]string{
			"empty":         {""},
			"bad regexp":    {"(unclosed"},
			"matches empty": {"a*"},
			"bad utf8":      {"\xff"},
			"too long":      {strings.Repeat("a", DefaultMaxPatternLen+1)},
		} {
			_, err := base.WithAllowList(p)
			assert.ErrorIs(t, err, ErrInvalidRule, name)
		}
		_, err := base.WithAllowList(make([]string, DefaultMaxRules+1))
		assert.ErrorIs(t, err, ErrTooManyRules)
		var nilSet *Compiled
		_, err = nilSet.WithAllowList(nil)
		assert.Error(t, err)
	})
}

func TestBlockCounter(t *testing.T) {
	for _, n := range []int{0, -1, 21} {
		_, err := NewBlockCounter(n)
		assert.ErrorIs(t, err, ErrInvalidBlockLimit, n)
	}
	for _, n := range []int{1, DefaultBlocksBeforeTerminate, 20} {
		bc, err := NewBlockCounter(n)
		require.NoError(t, err)
		for i := 1; i < n; i++ {
			assert.False(t, bc.Record(), "block %d of %d", i, n)
		}
		assert.True(t, bc.Record(), "exactly the %dth block", n)
		assert.True(t, bc.Record(), "stays terminated")
		assert.Equal(t, n, bc.Count())
	}
	var nilCounter *BlockCounter
	assert.True(t, nilCounter.Record())
}
