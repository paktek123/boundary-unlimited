// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbooks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func TestVerifiedCallerResolver(t *testing.T) {
	canary := "canary-secret-grant-string"
	cases := []struct {
		name     string
		verify   verifyFunc
		wantErr  bool
		wantUser string
	}{
		{
			name: "verify error denies with fixed reason",
			verify: func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
				return auth.VerifyResults{Error: errors.New(canary)}
			},
			wantErr: true,
		},
		{
			name: "anonymous user denies",
			verify: func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
				return auth.VerifyResults{UserId: "u_anon"}
			},
			wantErr: true,
		},
		{
			name: "empty user id denies",
			verify: func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
				return auth.VerifyResults{}
			},
			wantErr: true,
		},
		{
			name: "forbidden without identity denies",
			verify: func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
				return auth.VerifyResults{Error: handlers.ForbiddenError()}
			},
			wantErr: true,
		},
		{
			name: "forbidden for an identified user still resolves (no grant)",
			verify: func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
				return auth.VerifyResults{UserId: "u_1", Error: handlers.ForbiddenError()}
			},
			wantUser: "u_1",
		},
		{
			name: "unauthenticated error denies",
			verify: func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
				return auth.VerifyResults{UserId: "u_1", Error: handlers.UnauthenticatedError()}
			},
			wantErr: true,
		},
		{
			name: "authenticated user resolves",
			verify: func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults {
				return auth.VerifyResults{UserId: "u_1"}
			},
			wantUser: "u_1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &VerifiedCallerResolver{verify: tc.verify}
			c, err := r.Caller(context.Background())
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if err != errUnauthenticated || strings.Contains(err.Error(), canary) {
					t.Fatalf("expected fixed reason, got %q", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.UserId != tc.wantUser {
				t.Fatalf("UserId = %q, want %q", c.UserId, tc.wantUser)
			}
		})
	}

	t.Run("nil verifier fails closed", func(t *testing.T) {
		if _, err := (&VerifiedCallerResolver{}).Caller(context.Background()); err == nil {
			t.Fatal("expected error")
		}
	})
}
