// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbooks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/runbook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	scopeA = "o_1234567890"
	scopeB = "o_0987654321"
	sha40  = "0123456789abcdef0123456789abcdef01234567"
	canary = "CANARY-SCRIPT-BODY-9f3a"
)

type recEmitter struct {
	events []WriteEvent
	err    error
}

func (r *recEmitter) Emit(_ context.Context, e WriteEvent) error {
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, e)
	return nil
}

func acl(t *testing.T, scope string, grants ...string) perms.ACL {
	t.Helper()
	var gs []perms.Grant
	for _, g := range grants {
		p, err := perms.Parse(context.Background(), perms.GrantTuple{RoleScopeId: scope, GrantScopeId: scope, Grant: g})
		require.NoError(t, err, g)
		gs = append(gs, p)
	}
	return perms.NewACL(gs...)
}

func newSvc(t *testing.T) (*Service, *recEmitter, *runbook.MemRepository) {
	t.Helper()
	repo := runbook.NewMemRepository()
	em := &recEmitter{}
	n := 0
	s, err := NewService(repo, em,
		WithClock(func() time.Time { return time.Unix(1700000000, 0) }),
		WithIdGenerator(func(context.Context) (string, error) { n++; return fmt.Sprintf("rb_%010d", n), nil }))
	require.NoError(t, err)
	return s, em, repo
}

func admin(t *testing.T) Caller {
	return Caller{UserId: "u_1234567890", ACL: acl(t, scopeA,
		"ids=*;type=runbook;actions=create,list,read,update,delete")}
}

func req(script string) Request {
	return Request{
		ScopeId: scopeA, CommitSHA: sha40, ScriptPath: "ops/run.sh",
		Definition: runbook.Definition{
			Name: "restart", Interpreter: runbook.InterpreterPosixSh, Script: []byte(script),
			Selector: runbook.TargetSelector{AllTargets: true},
		},
	}
}

func TestCRUDAndAudit(t *testing.T) {
	ctx := context.Background()
	s, em, _ := newSvc(t)
	c := admin(t)
	d, err := s.Create(ctx, c, req("echo "+canary+"\n"))
	require.NoError(t, err)
	assert.Equal(t, uint32(1), d.Version)
	got, err := s.Get(ctx, c, d.Id)
	require.NoError(t, err)
	assert.Equal(t, d.Id, got.Id)
	l, err := s.List(ctx, c, scopeA)
	require.NoError(t, err)
	require.Len(t, l, 1)

	r := req("echo changed\n")
	r.Version = 1
	r.Definition.Description = "d"
	u, err := s.Update(ctx, c, d.Id, r)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), u.Version)
	_, err = s.Update(ctx, c, d.Id, r) // stale version
	assert.ErrorIs(t, err, ErrConflict)

	require.NoError(t, s.Delete(ctx, c, d.Id))
	_, err = s.Get(ctx, c, d.Id)
	assert.Error(t, err)

	var ops []string
	for _, e := range em.events {
		ops = append(ops, e.Op)
		assert.NotContains(t, fmt.Sprintf("%+v", e), canary)
	}
	assert.Equal(t, []string{"create", "update", "delete"}, ops)
}

func TestHandlerRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newSvc(t)
	c := admin(t)
	for name, mut := range map[string]func(*Request){
		"branch ref": func(r *Request) { r.CommitSHA = "main" },
		"tag ref":    func(r *Request) { r.CommitSHA = "v1.0.0" },
		"short sha":  func(r *Request) { r.CommitSHA = "0123abc" },
		"reserved name": func(r *Request) {
			r.Definition.Parameters = []runbook.Parameter{{Name: "PATH", Type: runbook.TypeBool}}
		},
		"lint eval": func(r *Request) {
			r.Definition.Parameters = []runbook.Parameter{{Name: "HOST", Type: runbook.TypeBool}}
			r.Definition.Script = []byte("eval \"$HOST\"\n")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := req("echo hi\n")
			mut(&r)
			_, err := s.Create(ctx, c, r)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalid)
			assert.False(t, strings.Contains(err.Error(), canary))
		})
	}
}

func TestCanaryNotInErrors(t *testing.T) {
	s, _, _ := newSvc(t)
	r := req("eval \"$HOST\" " + canary + "\n")
	r.Definition.Parameters = []runbook.Parameter{{Name: "HOST", Type: runbook.TypeBool}}
	_, err := s.Create(context.Background(), admin(t), r)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), canary)
}

func TestAuthorization(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newSvc(t)
	d, err := s.Create(ctx, admin(t), req("echo hi\n"))
	require.NoError(t, err)

	// Wildcard grants never cover runbooks.
	wild := Caller{UserId: "u_1234567890", ACL: acl(t, scopeA, "ids=*;type=*;actions=*")}
	// Explicit grant in another scope.
	other := Caller{UserId: "u_1234567890", ACL: acl(t, scopeB, "ids=*;type=runbook;actions=create,list,read,update,delete")}
	for name, c := range map[string]Caller{"wildcard": wild, "other scope": other, "anonymous": {}} {
		t.Run(name, func(t *testing.T) {
			_, err := s.Get(ctx, c, d.Id)
			assert.ErrorIs(t, err, ErrForbidden)
			_, err = s.List(ctx, c, scopeA)
			assert.ErrorIs(t, err, ErrForbidden)
			_, err = s.Create(ctx, c, req("echo hi\n"))
			assert.ErrorIs(t, err, ErrForbidden)
			_, err = s.Update(ctx, c, d.Id, req("echo hi\n"))
			assert.ErrorIs(t, err, ErrForbidden)
			assert.ErrorIs(t, s.Delete(ctx, c, d.Id), ErrForbidden)
		})
	}
	// A missing id is indistinguishable from forbidden.
	_, err = s.Get(ctx, other, "rb_missing000")
	assert.ErrorIs(t, err, ErrForbidden)

	// List-only grant cannot read.
	lo := Caller{UserId: "u_1234567890", ACL: acl(t, scopeA, "ids=*;type=runbook;actions=list")}
	l, err := s.List(ctx, lo, scopeA)
	require.NoError(t, err)
	assert.Empty(t, l)
}

func TestAuditFailureFailsClosed(t *testing.T) {
	ctx := context.Background()
	s, em, repo := newSvc(t)
	c := admin(t)
	d, err := s.Create(ctx, c, req("echo hi\n"))
	require.NoError(t, err)

	em.err = errors.New("sink down")
	second := req("echo hi2\n")
	second.Definition.Name = "second"
	_, err = s.Create(ctx, c, second)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrConflict, "must fail at the audit step, not on a name clash")
	l, _ := repo.List(ctx, scopeA)
	assert.Len(t, l, 1, "unaudited create must be rolled back")

	// The failed create must leave its name free for a retry.
	em.err = nil
	retry, err := s.Create(ctx, c, second)
	require.NoError(t, err)
	require.NoError(t, s.Delete(ctx, c, retry.Id))

	r2 := req("echo v2\n")
	r2.Version = d.Version
	u, err := s.Update(ctx, c, d.Id, r2)
	require.NoError(t, err)
	em.err = errors.New("sink down")
	r3 := req("echo v3\n")
	r3.Version = u.Version
	_, err = s.Update(ctx, c, d.Id, r3)
	require.Error(t, err)
	got, err := repo.Get(ctx, d.Id)
	require.NoError(t, err)
	assert.Equal(t, u.ScriptSHA256, got.ScriptSHA256, "unaudited update must be reverted")

	require.Error(t, s.Delete(ctx, c, d.Id))
	_, err = repo.Get(ctx, d.Id)
	assert.NoError(t, err, "unaudited delete must keep the definition")
}

func TestRunNotSupported(t *testing.T) {
	s, _, _ := newSvc(t)
	assert.ErrorIs(t, s.Run(context.Background(), admin(t), "rb_1234567890"), ErrRunNotSupported)
	assert.ErrorIs(t, s.Run(context.Background(), Caller{}, ""), ErrRunNotSupported)
}

func TestNewServiceRequiresDeps(t *testing.T) {
	_, err := NewService(nil, nil)
	assert.Error(t, err)
}
