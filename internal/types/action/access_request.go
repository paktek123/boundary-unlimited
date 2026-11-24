// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package action

import "github.com/hashicorp/boundary/internal/types/resource"

var (
	// AccessRequestIdActions are the actions that can be granted on an
	// individual access request. Approve is never covered by a wildcard grant.
	AccessRequestIdActions = NewActionSet(Read, Cancel, Approve, Deny, Revoke)

	// AccessRequestCollectionActions are the actions that can be granted on
	// the access request collection.
	AccessRequestCollectionActions = NewActionSet(Create, List)
)

func init() {
	RegisterResource(resource.AccessRequest, AccessRequestIdActions, AccessRequestCollectionActions)
}
