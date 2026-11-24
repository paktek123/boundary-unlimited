// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequests

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func TestVerifiedActorResolverErrors(t *testing.T) {
	canary := "canary-secret-grant-string"
	cases := map[string]verifyFunc{
		"verify error": func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
			return auth.VerifyResults{Error: errors.New(canary)}
		},
		"anonymous": func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
			return auth.VerifyResults{UserId: "u_anon"}
		},
		"empty user": func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
			return auth.VerifyResults{}
		},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			for _, scopeId := range []string{"", "o_1234567890"} {
				_, err := (&VerifiedActorResolver{verify: v}).Actor(context.Background(), scopeId)
				if err != errUnauthenticated || strings.Contains(err.Error(), canary) {
					t.Fatalf("expected fixed reason, got %v", err)
				}
			}
		})
	}
	if _, err := (&VerifiedActorResolver{}).Actor(context.Background(), ""); err != errUnauthenticated {
		t.Fatalf("nil verifier must fail closed, got %v", err)
	}
	var nilResolver *VerifiedActorResolver
	if _, err := nilResolver.Actor(context.Background(), ""); err != errUnauthenticated {
		t.Fatalf("nil resolver must fail closed, got %v", err)
	}
}

func TestVerifiedActorResolverAuthenticateOnly(t *testing.T) {
	r := &VerifiedActorResolver{verify: func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
		return auth.VerifyResults{UserId: "u_1"}
	}}
	a, err := r.Actor(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Id != "u_1" || a.CanApprove || len(a.Grants) != 0 {
		t.Fatalf("unexpected actor %+v", a)
	}
	// A verified user whose ACL is empty can never approve in a scope.
	a, err = r.Actor(context.Background(), "o_1234567890")
	if err != nil {
		t.Fatal(err)
	}
	if a.CanApprove {
		t.Fatal("empty ACL must not authorize approve")
	}
}

func aclFor(t *testing.T, scopeId string, grants ...string) perms.ACL {
	t.Helper()
	var parsed []perms.Grant
	for _, g := range grants {
		pg, err := perms.Parse(context.Background(), perms.GrantTuple{RoleScopeId: scopeId, GrantScopeId: scopeId, Grant: g})
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, pg)
	}
	return perms.NewACL(parsed...)
}

func TestCanApprove(t *testing.T) {
	const scopeA, scopeB = "o_1234567890", "o_0987654321"
	const user = "u_1234567890"
	cases := []struct {
		name   string
		grants []string
		scope  string
		want   bool
	}{
		{"explicit approve in scope", []string{"ids=*;type=access-request;actions=approve"}, scopeA, true},
		{"approve in A does not allow B", []string{"ids=*;type=access-request;actions=approve"}, scopeB, false},
		{"read-only caller", []string{"ids=*;type=access-request;actions=read,list"}, scopeA, false},
		{"actions wildcard", []string{"ids=*;type=access-request;actions=*"}, scopeA, false},
		{"type wildcard", []string{"ids=*;type=*;actions=*"}, scopeA, false},
		{"no grants", nil, scopeA, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := canApprove(aclFor(t, scopeA, tc.grants...), user, tc.scope); got != tc.want {
				t.Fatalf("canApprove = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestVerifiedActorResolverMalformedScope(t *testing.T) {
	r := &VerifiedActorResolver{verify: func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
		return auth.VerifyResults{UserId: "u_1"}
	}}
	for _, scopeId := range []string{"bogus", "x_123", "u_1"} {
		if _, err := r.Actor(context.Background(), scopeId); err != errUnauthenticated {
			t.Fatalf("scope %q: expected fixed refusal, got %v", scopeId, err)
		}
	}
	for _, scopeId := range []string{"global", "o_1234567890", "p_1234567890"} {
		if _, err := r.Actor(context.Background(), scopeId); err != nil {
			t.Fatalf("scope %q: %v", scopeId, err)
		}
	}
}
