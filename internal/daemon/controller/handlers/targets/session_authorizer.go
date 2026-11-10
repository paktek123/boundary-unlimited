// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package targets

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/policyhook"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
)

// authorizeSessionAction is the action name sent to the external authorizer.
const authorizeSessionAction = "authorize-session"

// SessionAuthorizer is the external authorizer consulted by AuthorizeSession
// after the built-in grants allowed the request. *policyhook.Hook implements
// it. The result is the AND of the grants and the authorizer: it can deny,
// never grant. See docs/rfc/external-authorizer.md.
type SessionAuthorizer interface {
	Authorize(ctx context.Context, requestID string, grantsAllowed bool, in policyhook.Input) (policyhook.Decision, policyhook.Reason)
}

// WithSessionAuthorizer returns a copy of the Service that consults a for
// every AuthorizeSession call that the built-in grants allowed. A nil a leaves
// the Service unchanged. Nothing in the controller configuration selects an
// authorizer yet.
func (s Service) WithSessionAuthorizer(a SessionAuthorizer) Service {
	s.sessionAuthorizer = a
	return s
}

// externalAuthorize returns nil when no authorizer is configured or when the
// authorizer allowed the request. Every other outcome, including errors,
// timeouts and invalid responses, is the generic forbidden error: the client
// never learns the reason.
func (s Service) externalAuthorize(ctx context.Context, requestID, userID string, scope *scopes.ScopeInfo, t target.Target, hostID string) error {
	if s.sessionAuthorizer == nil {
		return nil
	}
	in := policyhook.Input{
		PrincipalID: userID,
		UserID:      userID,
		TargetID:    t.GetPublicId(),
		TargetType:  t.GetType().String(),
		HostID:      hostID,
		Action:      authorizeSessionAction,
		RequestTime: time.Now().UTC(),
	}
	if scope != nil {
		in.ScopeIDs = []string{scope.GetId()}
	} else if pid := t.GetProjectId(); pid != "" {
		in.ScopeIDs = []string{pid}
	}
	d, _ := s.sessionAuthorizer.Authorize(ctx, requestID, true, in)
	if d != policyhook.Allow {
		return handlers.ForbiddenError()
	}
	return nil
}
