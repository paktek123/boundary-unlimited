// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/perms"
)

// Reasons used in Dropped by MergeOverlay in addition to those in overlay.go.
const (
	ReasonWildcardGrant = "wildcard grant without approver snapshot"
	ReasonScopeMismatch = "request scope differs from requested scope"
)

// ErrOverlayUnavailable is wrapped by the error MergeOverlay returns when the
// overlay contributed nothing because its source or clock failed. It never
// carries grant strings or request contents.
var ErrOverlayUnavailable = errors.New("accessrequest: overlay unavailable")

// GrantOverlaySource supplies the requests that may contribute overlay grants
// for a user in a scope. Implementations return candidate requests only; the
// time window, state and grant validity are re-checked by MergeOverlay, so a
// source that returns too much cannot extend access.
//
// Nothing caches in this package. Any future cache of an overlay result must
// have a TTL of at most a few seconds and must never outlive the earliest
// ExpiresAt of the requests it holds.
type GrantOverlaySource interface {
	OverlayRequests(ctx context.Context, userId, reqScopeId string) ([]Request, error)
}

// RepositorySource adapts a Repository to a GrantOverlaySource.
type RepositorySource struct {
	Repo Repository
}

// OverlayRequests implements GrantOverlaySource.
func (s RepositorySource) OverlayRequests(ctx context.Context, userId, reqScopeId string) ([]Request, error) {
	if s.Repo == nil || userId == "" || reqScopeId == "" {
		return nil, ErrInvalidInput
	}
	all, err := s.Repo.List(ctx, ListFilter{RequesterId: userId, States: []State{StateApproved}})
	if err != nil {
		return nil, err
	}
	var out []Request
	for _, r := range all {
		if r.ScopeId == reqScopeId {
			out = append(out, r)
		}
	}
	return out, nil
}

// MergeResult is the outcome of MergeOverlay.
type MergeResult struct {
	// Grants is base followed by the overlay grants, in that order. The base
	// grants are always present and unchanged.
	Grants []perms.GrantTuple
	// Events holds one overlay-authorized event per overlay grant added.
	Events []Event
	// Dropped lists requests and grants that contributed nothing. It never
	// contains grant strings.
	Dropped []Dropped
}

// MergeOverlay appends the grants of approved, unexpired access requests to
// base after normal grant resolution. It never removes or alters base grants.
//
// It fails closed: if src or clock is nil or fails, now is the zero time, or
// the source returns an error, no overlay grant is added and the returned
// error wraps ErrOverlayUnavailable; MergeResult.Grants still holds the
// unchanged base. Individual malformed requests and unparsable grants are
// skipped and reported in Dropped, without an error.
//
// Overlay grants are limited to reqScopeId (the grant scope of every overlay
// tuple is the request's scope). A wildcard grant (ids and actions both "*",
// or "*") is dropped: Request carries no approver grant snapshot yet, so
// there is nothing to prove the approver held exactly that grant.
func MergeOverlay(ctx context.Context, base []perms.GrantTuple, userId, reqScopeId string, src GrantOverlaySource, clock Clock) (MergeResult, error) {
	res := MergeResult{Grants: append([]perms.GrantTuple(nil), base...)}
	if src == nil || clock == nil || userId == "" || reqScopeId == "" {
		return res, fmt.Errorf("%w: missing source, clock or identifiers", ErrOverlayUnavailable)
	}
	now := safeNow(clock)
	if now.IsZero() {
		return res, fmt.Errorf("%w: clock failed", ErrOverlayUnavailable)
	}
	reqs, err := safeRequests(ctx, src, userId, reqScopeId)
	if err != nil {
		return res, fmt.Errorf("%w: source failed", ErrOverlayUnavailable)
	}
	// Only requests for this user and scope may contribute.
	var eligible []Request
	byId := make(map[string]Request, len(reqs))
	for _, r := range reqs {
		if r.RequesterId != userId {
			res.Dropped = append(res.Dropped, Dropped{RequestId: r.Id, GrantIndex: -1, Reason: ReasonMalformedRequest})
			continue
		}
		if r.ScopeId != reqScopeId {
			res.Dropped = append(res.Dropped, Dropped{RequestId: r.Id, GrantIndex: -1, Reason: ReasonScopeMismatch})
			continue
		}
		eligible = append(eligible, r)
		byId[r.Id] = r
	}
	timed, dropped := EffectiveGrants(ctx, eligible, now)
	res.Dropped = append(res.Dropped, dropped...)
	for _, tg := range timed {
		if isWildcardGrant(normalizeGrant(tg.Grant)) {
			res.Dropped = append(res.Dropped, Dropped{RequestId: tg.RequestId, GrantIndex: -1, Reason: ReasonWildcardGrant})
			continue
		}
		ev, err := NewOverlayAuthorizedEvent(byId[tg.RequestId], tg.Grant, now)
		if err != nil {
			// An event that cannot be built cleanly (for example a sensitive
			// looking field) means the grant is not authorised.
			res.Dropped = append(res.Dropped, Dropped{RequestId: tg.RequestId, GrantIndex: -1, Reason: ReasonMalformedRequest})
			continue
		}
		res.Grants = append(res.Grants, perms.GrantTuple{
			RoleScopeId:  tg.ScopeId,
			GrantScopeId: tg.ScopeId,
			Grant:        strings.TrimSpace(tg.Grant),
		})
		res.Events = append(res.Events, ev)
	}
	return res, nil
}

func safeNow(c Clock) (t time.Time) {
	defer func() {
		if recover() != nil {
			t = time.Time{}
		}
	}()
	return c.Now()
}

func safeRequests(ctx context.Context, src GrantOverlaySource, userId, scopeId string) (reqs []Request, err error) {
	defer func() {
		if recover() != nil {
			reqs, err = nil, ErrOverlayUnavailable
		}
	}()
	return src.OverlayRequests(ctx, userId, scopeId)
}
