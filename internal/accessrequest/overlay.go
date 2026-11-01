// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package accessrequest

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/perms"
)

// TimedGrant is a grant string contributed by an approved request, valid in
// the half-open interval [NotBefore, NotAfter).
type TimedGrant struct {
	RequestId string
	ScopeId   string
	// Grant is exactly one of the requested grant strings, unmodified.
	Grant     string
	NotBefore time.Time
	NotAfter  time.Time
}

// Dropped explains why a request or one of its grants contributed nothing
// although the request was approved and unexpired. It never contains the grant
// string. GrantIndex is -1 when the whole request was malformed.
type Dropped struct {
	RequestId  string
	GrantIndex int
	Reason     string
}

// Reasons used in Dropped.
const (
	ReasonMalformedRequest = "malformed request"
	ReasonInvalidGrant     = "grant does not parse"
)

// EffectiveGrants is a pure function that returns the grants contributed by
// requests that are approved, already decided (now >= DecidedAt) and not yet
// expired (now < ExpiresAt; the expiry instant itself counts as expired).
// Pending, denied, cancelled, expired, revoked and unknown-state requests
// contribute nothing. Grants that fail perms.Parse, and malformed approved
// requests, contribute nothing and are reported in the second result
// (fail closed). Grants are returned exactly as requested and are scoped to
// the request's ScopeId; they are never widened or rewritten. The caller
// merges them after normal grant resolution; this package does not.
//
// It does not read any store and not the system clock: now is supplied by
// the caller, and a caller that cannot determine now or load requests must
// not call it and must use no overlay at all.
func EffectiveGrants(ctx context.Context, requests []Request, now time.Time) ([]TimedGrant, []Dropped) {
	var out []TimedGrant
	var dropped []Dropped
	for _, r := range requests {
		if r.State != StateApproved {
			continue
		}
		if r.ExpiresAt.IsZero() || r.DecidedAt.IsZero() || !r.ExpiresAt.After(r.DecidedAt) {
			dropped = append(dropped, Dropped{RequestId: r.Id, GrantIndex: -1, Reason: ReasonMalformedRequest})
			continue
		}
		if r.Id == "" || r.ScopeId == "" || r.RequesterId == "" || len(r.Grants) == 0 {
			dropped = append(dropped, Dropped{RequestId: r.Id, GrantIndex: -1, Reason: ReasonMalformedRequest})
			continue
		}
		if now.Before(r.DecidedAt) || !now.Before(r.ExpiresAt) {
			continue
		}
		for i, g := range r.Grants {
			_, err := perms.Parse(ctx, perms.GrantTuple{
				RoleScopeId:  r.ScopeId,
				GrantScopeId: r.ScopeId,
				Grant:        g,
			})
			if err != nil {
				dropped = append(dropped, Dropped{RequestId: r.Id, GrantIndex: i, Reason: ReasonInvalidGrant})
				continue
			}
			out = append(out, TimedGrant{
				RequestId: r.Id,
				ScopeId:   r.ScopeId,
				Grant:     g,
				NotBefore: r.DecidedAt,
				NotAfter:  r.ExpiresAt,
			})
		}
	}
	return out, dropped
}
