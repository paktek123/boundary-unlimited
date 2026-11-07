// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package approval binds a runbook approval to exactly what was reviewed: the
// runbook reference, the pinned commit SHA, the SHA-256 of the script bytes and
// the set of parameter NAMES. Parameter values are never part of a binding, of
// its canonical encoding or of any error text. The package performs no I/O and
// is not wired into any request path yet.
package approval

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/boundary/internal/runbook"
	"github.com/hashicorp/boundary/internal/runbook/source"
)

// Errors returned by Bind and Verify. None of them contains a value.
var (
	ErrEmptyBinding = errors.New("approval: binding is empty or incomplete")
	ErrMismatch     = errors.New("approval: binding does not match the approved binding")
)

// Binding is what an approval covers. Compare it only with Verify.
type Binding struct {
	RunbookRef string
	CommitSHA  string
	ScriptHash string
	// ParamNames is the sorted, duplicate-free set of parameter names.
	ParamNames []string
}

// Bind builds the Binding for a definition fetched and pinned as pinned. It
// fails closed on an invalid pin, an empty runbook name, an empty or duplicate
// parameter name, or a script that does not match the pin.
func Bind(def runbook.Definition, pinned source.Pin) (Binding, error) {
	if def.Name == "" {
		return Binding{}, ErrEmptyBinding
	}
	if err := source.ValidateSHA(pinned.SHA); err != nil {
		return Binding{}, ErrEmptyBinding
	}
	if err := source.Verify(pinned, def.Script); err != nil {
		return Binding{}, ErrMismatch
	}
	names := make([]string, 0, len(def.Parameters))
	seen := make(map[string]struct{}, len(def.Parameters))
	for _, p := range def.Parameters {
		if p.Name == "" {
			return Binding{}, ErrEmptyBinding
		}
		if _, dup := seen[p.Name]; dup {
			return Binding{}, ErrEmptyBinding
		}
		seen[p.Name] = struct{}{}
		names = append(names, p.Name)
	}
	sort.Strings(names)
	b := Binding{RunbookRef: def.Name, CommitSHA: pinned.SHA, ScriptHash: pinned.ScriptSHA256, ParamNames: names}
	if !b.complete() {
		return Binding{}, ErrEmptyBinding
	}
	return b, nil
}

func (b Binding) complete() bool {
	if b.RunbookRef == "" || b.CommitSHA == "" || b.ScriptHash == "" {
		return false
	}
	for _, n := range b.ParamNames {
		if n == "" {
			return false
		}
	}
	return true
}

// Canonical returns a deterministic encoding: length-prefixed fields with the
// parameter names sorted, so no field can bleed into another.
func (b Binding) Canonical() string {
	names := append([]string(nil), b.ParamNames...)
	sort.Strings(names)
	var sb strings.Builder
	sb.WriteString("runbook-approval-binding/v1\n")
	for _, f := range []string{b.RunbookRef, b.CommitSHA, b.ScriptHash} {
		fmt.Fprintf(&sb, "%d:%s\n", len(f), f)
	}
	fmt.Fprintf(&sb, "params:%d\n", len(names))
	for _, n := range names {
		fmt.Fprintf(&sb, "%d:%s\n", len(n), n)
	}
	return sb.String()
}

func eq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Verify checks that current is exactly the approved binding. Any difference
// (runbook, SHA, script hash, added, removed or renamed parameter) or an empty
// binding on either side fails closed.
func Verify(approved, current Binding) error {
	if !approved.complete() || !current.complete() {
		return ErrEmptyBinding
	}
	// Compare canonical forms so unsorted input cannot match by accident.
	if !eq(approved.Canonical(), current.Canonical()) {
		return ErrMismatch
	}
	return nil
}

// String implements fmt.Stringer and lists names only.
func (b Binding) String() string {
	return fmt.Sprintf("Binding{runbook=%q sha=%q params=%v}", b.RunbookRef, b.CommitSHA, b.ParamNames)
}
