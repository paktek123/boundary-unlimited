// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequests

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func fakeVerify(res auth.VerifyResults) verifyFunc {
	return func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults { return res }
}

func TestVerifiedActorResolverUnauthenticated(t *testing.T) {
	canary := "canary-secret-grant-string"
	cases := map[string]auth.VerifyResults{
		"unknown error":              {UserId: "u_1", Error: errors.New(canary), AuthenticationFinished: true},
		"forbidden but not finished": {UserId: "u_1", Error: handlers.ForbiddenError()},
		"unauthenticated":            {UserId: "u_anon", Error: handlers.UnauthenticatedError()},
		"anonymous":                  {UserId: "u_anon"},
		"recovery user":              {UserId: globals.RecoveryUserId, AuthenticationFinished: true},
		"empty user":                 {},
	}
	for name, res := range cases {
		t.Run(name, func(t *testing.T) {
			for _, scopeId := range []string{"", "o_1234567890"} {
				_, err := (&VerifiedActorResolver{verify: fakeVerify(res)}).Actor(context.Background(), scopeId)
				if err != errUnauthenticated || strings.Contains(err.Error(), canary) {
					t.Fatalf("scope %q: expected fixed reason, got %v", scopeId, err)
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

func TestVerifiedActorResolverMalformedScope(t *testing.T) {
	r := &VerifiedActorResolver{verify: fakeVerify(auth.VerifyResults{UserId: "u_1"})}
	for _, s := range []string{"x", "u_1234567890", "o", "p-1"} {
		if _, err := r.Actor(context.Background(), s); err != errUnauthenticated {
			t.Fatalf("scope %q: expected unauthenticated, got %v", s, err)
		}
	}
}

// An authenticated user who is not granted approve gets a PermissionDenied
// result from auth.Verify. That must resolve to an actor that cannot approve,
// not to unauthenticated, otherwise every ordinary user would look anonymous.
func TestVerifiedActorResolverAuthenticatedWithoutGrant(t *testing.T) {
	forbidden := auth.VerifyResults{UserId: "u_1", Error: handlers.ForbiddenError(), AuthenticationFinished: true}
	r := &VerifiedActorResolver{verify: fakeVerify(forbidden)}
	for _, scopeId := range []string{"", "o_1234567890", "p_1234567890", "global"} {
		a, err := r.Actor(context.Background(), scopeId)
		if err != nil {
			t.Fatalf("scope %q: unexpected error %v", scopeId, err)
		}
		if a.Id != "u_1" || a.CanApprove || len(a.Grants) != 0 {
			t.Fatalf("scope %q: unexpected actor %+v", scopeId, a)
		}
	}
}

func TestVerifiedActorResolverAuthorized(t *testing.T) {
	r := &VerifiedActorResolver{verify: fakeVerify(auth.VerifyResults{UserId: "u_1", AuthenticationFinished: true})}
	// authenticate-only never reports CanApprove, even when authorized.
	a, err := r.Actor(context.Background(), "")
	if err != nil || a.Id != "u_1" || a.CanApprove {
		t.Fatalf("authenticate-only: %+v, %v", a, err)
	}
	a, err = r.Actor(context.Background(), "o_1234567890")
	if err != nil || a.Id != "u_1" || !a.CanApprove || len(a.Grants) != 0 {
		t.Fatalf("scoped: %+v, %v", a, err)
	}
}

// auth.Option is a function over an unexported type, so a test outside the
// auth package cannot apply the options. Pin that the resolver calls Verify for
// the access-request type with exactly four options (scope, action, anonymous
// not allowed, recovery not allowed). The real-token path needs a database
// harness and is covered by the controller integration test (not in this PR).
func TestVerifiedActorResolverPassesAuthOptions(t *testing.T) {
	var got int
	r := &VerifiedActorResolver{verify: func(_ context.Context, typ resource.Type, opts ...auth.Option) auth.VerifyResults {
		got = len(opts)
		if typ != resource.AccessRequest {
			t.Fatalf("verified type %v, want access-request", typ)
		}
		return auth.VerifyResults{UserId: "u_1", AuthenticationFinished: true}
	}}
	for _, scopeId := range []string{"", "o_1234567890"} {
		got = 0
		if _, err := r.Actor(context.Background(), scopeId); err != nil {
			t.Fatal(err)
		}
		if got != 4 {
			t.Fatalf("scope %q: passed %d auth options, want 4", scopeId, got)
		}
	}
}
