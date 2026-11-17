// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbook

// Validate re-checks the invariants a stored definition must hold. Repository
// implementations in other packages call it on every write so a hand-built
// StoredDefinition cannot bypass NewStoredDefinition. Errors wrap
// ErrInvalidInput and never contain script content or parameter values.
func (s StoredDefinition) Validate() error { return s.validate() }
