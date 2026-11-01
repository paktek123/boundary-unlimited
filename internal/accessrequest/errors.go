// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package accessrequest

import "errors"

// Typed errors returned by the lifecycle functions. Callers match them with
// errors.Is. Every error leaves the request unchanged.
var (
	ErrInvalidInput      = errors.New("accessrequest: invalid input")
	ErrInvalidState      = errors.New("accessrequest: invalid state")
	ErrInvalidTransition = errors.New("accessrequest: invalid state transition")
	ErrSelfApproval      = errors.New("accessrequest: requester cannot decide their own request")
	ErrNotRequester      = errors.New("accessrequest: only the requester may cancel")
	ErrPendingExpired    = errors.New("accessrequest: pending request is past its maximum age")
	ErrDurationTooLong   = errors.New("accessrequest: requested duration exceeds the maximum")
)
