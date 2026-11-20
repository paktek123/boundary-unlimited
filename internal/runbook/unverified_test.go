// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbook

import (
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/runbook/source"
)

func mustUnverified(t *testing.T) StoredDefinition {
	t.Helper()
	d, err := NewUnverifiedStoredDefinition("rb_1", "p_1", "restart", "", InterpreterPosixSh, testDef().Parameters, TargetSelector{}, testSHA, "runbooks/restart.sh")
	if err != nil {
		t.Fatalf("NewUnverifiedStoredDefinition: %v", err)
	}
	return d
}

func TestUnverifiedDefinition(t *testing.T) {
	d := mustUnverified(t)
	if d.Verified() || d.ScriptSHA256 != "" {
		t.Fatal("definition built from a pin only must be unverified")
	}
	// Run and approval binding use source.Verify: it must refuse the pin.
	if err := source.Verify(d.Pin(), []byte("echo hi\n")); err == nil {
		t.Fatal("source.Verify must refuse an unverified pin")
	}
	if !mustStored(t, "rb_2", "p_1").Verified() {
		t.Fatal("definition built with script bytes must be verified")
	}
}

func TestUnverifiedRejectsBadPins(t *testing.T) {
	for name, tc := range map[string]struct{ sha, path string }{
		"branch":    {"main", "a.sh"},
		"short sha": {"0123abc", "a.sh"},
		"bad path":  {testSHA, "../a.sh"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewUnverifiedStoredDefinition("rb_1", "p_1", "restart", "", InterpreterPosixSh, nil, TargetSelector{}, tc.sha, tc.path)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("want ErrInvalidInput, got %v", err)
			}
		})
	}
}

func TestWithPinResetsVerification(t *testing.T) {
	v := mustStored(t, "rb_1", "p_1")
	other := "fedcba9876543210fedcba9876543210fedcba98"
	for name, tc := range map[string]struct {
		sha, path string
		verified  bool
	}{
		"same pin":    {v.SourceCommitSHA, v.ScriptPath, true},
		"new commit":  {other, v.ScriptPath, false},
		"new path":    {v.SourceCommitSHA, "runbooks/other.sh", false},
		"commit+path": {other, "runbooks/other.sh", false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := v.WithPin(tc.sha, tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if got.Verified() != tc.verified {
				t.Fatalf("Verified()=%v want %v", got.Verified(), tc.verified)
			}
		})
	}
	if _, err := v.WithPin("main", v.ScriptPath); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("branch pin must be rejected, got %v", err)
	}
	if !v.Verified() {
		t.Fatal("WithPin must not mutate the receiver")
	}
}
