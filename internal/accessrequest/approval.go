// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package accessrequest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ApproveAction is the action an approver must hold on the request scope.
const ApproveAction = "access-requests:approve"

// DefaultPolicyMaxTTL is the default maximum approved access duration.
const DefaultPolicyMaxTTL = 24 * time.Hour

// Additional typed errors for approval validation. None of them embeds grant
// strings, so they are safe to log and return to callers.
var (
	ErrApproverNotAuthorized = errors.New("accessrequest: approver lacks the approve action on the request scope")
	ErrGrantsNotHeld         = errors.New("accessrequest: approver does not hold every requested grant")
	ErrGrantsChanged         = errors.New("accessrequest: grants changed after approval")
	ErrWildcardGrant         = errors.New("accessrequest: wildcard grant requires an approver holding exactly that grant")
	ErrInvalidPolicy         = errors.New("accessrequest: invalid approval policy")
)

// ApproverContext describes the approver. All fields are supplied by the
// caller (resolved elsewhere); this package does no lookups.
type ApproverContext struct {
	Id string
	// CanApprove is true when the approver holds ApproveAction on the
	// request's scope.
	CanApprove bool
	// Grants are the approver's resolved grant strings.
	Grants []string
}

// ApprovalPolicy configures approval validation.
type ApprovalPolicy struct {
	// MaxTTL caps the approved duration. It must be positive; zero is not
	// "unbounded", it is invalid. Use DefaultApprovalPolicy for the default.
	MaxTTL time.Duration
}

// DefaultApprovalPolicy returns the default policy (24h maximum TTL).
func DefaultApprovalPolicy() ApprovalPolicy {
	return ApprovalPolicy{MaxTTL: DefaultPolicyMaxTTL}
}

// normalizeGrant canonicalises a grant string for comparison: surrounding
// space is trimmed, text is lower-cased and the ';'-separated segments are
// trimmed and sorted so that segment order does not matter. Comparison is
// case-insensitive by design (grant ids are lower-case in practice).
func normalizeGrant(g string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(g)), ";")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// GrantHash returns the hex SHA-256 over the sorted, de-duplicated,
// normalised grant strings. Entries are length-prefixed so different grant
// lists can never produce the same input.
func GrantHash(grants []string) string {
	norm := make([]string, 0, len(grants))
	seen := make(map[string]struct{}, len(grants))
	for _, g := range grants {
		n := normalizeGrant(g)
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		norm = append(norm, n)
	}
	sort.Strings(norm)
	h := sha256.New()
	for _, n := range norm {
		fmt.Fprintf(h, "%d:%s\n", len(n), n)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// isWildcardGrant reports whether the normalised grant is a catch-all: "*",
// or any grant whose ids and actions are both "*".
func isWildcardGrant(n string) bool {
	if n == "*" {
		return true
	}
	var idStar, actionsStar bool
	for _, seg := range strings.Split(n, ";") {
		k, v, ok := strings.Cut(seg, "=")
		if !ok {
			continue
		}
		switch k {
		case "id", "ids":
			if v == "*" {
				idStar = true
			}
		case "action", "actions":
			if v == "*" {
				actionsStar = true
			}
		}
	}
	return idStar && actionsStar
}

// ValidateApproval checks that approver may approve req at now under policy.
// It is a pure function and does not change req. Nothing here is a
// capability by itself: the caller must still call Approve/RecordApproval.
//
// Superset check limitation: grants are compared as normalised strings
// (exact match after trimming, lower-casing and segment sorting), not parsed
// with internal/perms, so an approver holding a broader grant that covers a
// requested narrower one is still rejected. This fails closed.
func ValidateApproval(req Request, approver ApproverContext, now time.Time, policy ApprovalPolicy) error {
	if policy.MaxTTL <= 0 {
		return fmt.Errorf("%w: max TTL must be positive", ErrInvalidPolicy)
	}
	if err := check(req, approver.Id, now); err != nil {
		return err
	}
	if approver.Id == req.RequesterId {
		return ErrSelfApproval
	}
	if !approver.CanApprove {
		return ErrApproverNotAuthorized
	}
	if len(req.Grants) == 0 {
		return fmt.Errorf("%w: at least one grant is required", ErrInvalidInput)
	}
	if req.Duration <= 0 {
		return fmt.Errorf("%w: duration must be positive", ErrInvalidInput)
	}
	if req.Duration > policy.MaxTTL {
		return ErrDurationTooLong
	}
	held := make(map[string]struct{}, len(approver.Grants))
	for _, g := range approver.Grants {
		held[normalizeGrant(g)] = struct{}{}
	}
	for _, g := range req.Grants {
		n := normalizeGrant(g)
		if n == "" {
			return fmt.Errorf("%w: empty grant", ErrInvalidInput)
		}
		_, ok := held[n]
		if isWildcardGrant(n) && !ok {
			return ErrWildcardGrant
		}
		if !ok {
			return ErrGrantsNotHeld
		}
	}
	if req.GrantHash != "" && req.GrantHash != GrantHash(req.Grants) {
		return ErrGrantsChanged
	}
	return nil
}

// RecordApproval validates the approval with ValidateApproval, applies
// Approve (limits from opt) and records the grant hash on the result. On any
// error the request is returned unchanged.
func RecordApproval(req Request, approver ApproverContext, now time.Time, policy ApprovalPolicy, opt ...Option) (Request, error) {
	if err := ValidateApproval(req, approver, now, policy); err != nil {
		return req, err
	}
	// The policy TTL is applied last so it is authoritative for this call.
	opts := append(append([]Option(nil), opt...), WithMaxDuration(policy.MaxTTL))
	out, err := Approve(req, approver.Id, now, opts...)
	if err != nil {
		return req, err
	}
	out.GrantHash = GrantHash(out.Grants)
	return out, nil
}

// VerifyApprovedGrants fails with ErrGrantsChanged unless an approved
// request still carries exactly the grants that were approved. A request
// approved without a recorded hash fails closed.
func VerifyApprovedGrants(req Request) error {
	if req.State != StateApproved {
		return fmt.Errorf("%w: not approved", ErrInvalidTransition)
	}
	if req.GrantHash == "" || req.GrantHash != GrantHash(req.Grants) {
		return ErrGrantsChanged
	}
	return nil
}
