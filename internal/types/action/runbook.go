// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package action

import "github.com/hashicorp/boundary/internal/types/resource"

var (
	// RunbookIdActions are the actions that can be granted on an individual
	// runbook. Execute is defined, but the ACL never authorizes it until the
	// runbook executor exists (see internal/perms).
	RunbookIdActions = NewActionSet(Read, Update, Delete, Execute)

	// RunbookCollectionActions are the actions that can be granted on the
	// runbook collection.
	RunbookCollectionActions = NewActionSet(Create, List)
)

func init() {
	RegisterResource(resource.Runbook, RunbookIdActions, RunbookCollectionActions)
}
