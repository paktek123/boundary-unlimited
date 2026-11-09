// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package notify

import "github.com/hashicorp/boundary/internal/netguard"

// ErrBlockedDestination is returned when a destination address is not
// permitted. The error never includes the host or address. It is the shared
// netguard error, so errors.Is works across packages.
var ErrBlockedDestination = netguard.ErrBlockedDestination

// Resolver resolves host names. *net.Resolver satisfies it.
type Resolver = netguard.Resolver
