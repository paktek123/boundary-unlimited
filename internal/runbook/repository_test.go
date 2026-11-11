// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbook

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/runbook/source"
)

const testSHA = "0123456789abcdef0123456789abcdef01234567"

func testDef() Definition {
	return Definition{
		Name:        "restart-service",
		Interpreter: InterpreterPosixSh,
		Parameters: []Parameter{
			{Name: "SERVICE", Type: TypeEnum, AllowedValues: []string{"web", "db"}, Required: true},
		},
		Script: []byte("systemctl restart \"$SERVICE\"\n"),
	}
}

func mustStored(t *testing.T, id, scope string) StoredDefinition {
	t.Helper()
	s, err := NewStoredDefinition(id, scope, testDef(), testSHA, "runbooks/restart.sh")
	if err != nil {
		t.Fatalf("NewStoredDefinition: %v", err)
	}
	return s
}

func TestNewStoredDefinition(t *testing.T) {
	good := mustStored(t, "rb_1", "p_1")
	if good.SourceCommitSHA != testSHA || len(good.ScriptSHA256) != 64 {
		t.Fatalf("pin not recorded: %+v", good)
	}
	if err := source.Verify(good.Pin(), testDef().Script); err != nil {
		t.Fatalf("pin does not verify the script: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(d *Definition, sha, path *string)
	}{
		{"branch ref", func(_ *Definition, sha, _ *string) { *sha = "main" }},
		{"tag ref", func(_ *Definition, sha, _ *string) { *sha = "v1.2.3" }},
		{"short sha", func(_ *Definition, sha, _ *string) { *sha = "abc1234" }},
		{"upper case sha", func(_ *Definition, sha, _ *string) { *sha = strings.ToUpper(testSHA) }},
		{"empty sha", func(_ *Definition, sha, _ *string) { *sha = "" }},
		{"path traversal", func(_ *Definition, _, p *string) { *p = "../x.sh" }},
		{"absolute path", func(_ *Definition, _, p *string) { *p = "/etc/passwd" }},
		{"reserved param name", func(d *Definition, _, _ *string) {
			d.Parameters = []Parameter{{Name: "LD_PRELOAD", Type: TypeBool}}
			d.Script = []byte("true\n")
		}},
		{"duplicate param", func(d *Definition, _, _ *string) {
			d.Parameters = append(d.Parameters, d.Parameters[0])
		}},
		{"unsupported interpreter", func(d *Definition, _, _ *string) { d.Interpreter = "bash" }},
		{"empty script", func(d *Definition, _, _ *string) { d.Script = nil }},
		{"empty name", func(d *Definition, _, _ *string) { d.Name = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, sha, path := testDef(), testSHA, "runbooks/restart.sh"
			tt.mutate(&d, &sha, &path)
			_, err := NewStoredDefinition("rb_1", "p_1", d, sha, path)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("want ErrInvalidInput, got %v", err)
			}
		})
	}
	if _, err := NewStoredDefinition("", "p_1", testDef(), testSHA, "a.sh"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty id: %v", err)
	}
}

func TestMemRepositoryRejectsHandBuiltDefinitions(t *testing.T) {
	ctx := context.Background()
	m := NewMemRepository()
	base := mustStored(t, "rb_1", "p_1")
	tests := []struct {
		name   string
		mutate func(s *StoredDefinition)
	}{
		{"floating ref", func(s *StoredDefinition) { s.SourceCommitSHA = "main" }},
		{"short sha", func(s *StoredDefinition) { s.SourceCommitSHA = "abc1234" }},
		{"bad script hash", func(s *StoredDefinition) { s.ScriptSHA256 = "nothex" }},
		{"upper script hash", func(s *StoredDefinition) { s.ScriptSHA256 = strings.Repeat("A", 64) }},
		{"bad path", func(s *StoredDefinition) { s.ScriptPath = "../x" }},
		{"reserved param", func(s *StoredDefinition) {
			s.Parameters = []Parameter{{Name: "PATH", Type: TypeBool}}
		}},
		{"dup param", func(s *StoredDefinition) {
			s.Parameters = []Parameter{{Name: "A", Type: TypeBool}, {Name: "A", Type: TypeBool}}
		}},
		{"bad interpreter", func(s *StoredDefinition) { s.Interpreter = "python" }},
		{"empty selector id", func(s *StoredDefinition) { s.Selector = TargetSelector{TargetIDs: []string{""}} }},
		{"wildcard selector id", func(s *StoredDefinition) { s.Selector = TargetSelector{TargetIDs: []string{"*"}} }},
		{"dup selector id", func(s *StoredDefinition) { s.Selector = TargetSelector{ScopeIDs: []string{"p_1", "p_1"}} }},
		{"too many selector ids", func(s *StoredDefinition) {
			ids := make([]string, MaxSelectorEntries+1)
			for i := range ids {
				ids[i] = fmt.Sprintf("ttcp_%d", i)
			}
			s.Selector = TargetSelector{TargetIDs: ids}
		}},
		{"all targets plus ids", func(s *StoredDefinition) {
			s.Selector = TargetSelector{AllTargets: true, TargetIDs: []string{"ttcp_1"}}
		}},
		{"nonzero version", func(s *StoredDefinition) { s.Version = 3 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := base
			s.Parameters = append([]Parameter(nil), base.Parameters...)
			tt.mutate(&s)
			if _, err := m.Create(ctx, s); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Create: want ErrInvalidInput, got %v", err)
			}
		})
	}
	if l, _ := m.List(ctx, "p_1"); len(l) != 0 {
		t.Fatalf("rejected definitions were stored: %d", len(l))
	}
}

func TestMemRepositoryCRUD(t *testing.T) {
	ctx := context.Background()
	m := NewMemRepository()
	a := mustStored(t, "rb_a", "p_1")
	got, err := m.Create(ctx, a)
	if err != nil || got.Version != 1 {
		t.Fatalf("Create: %v %+v", err, got)
	}
	if _, err := m.Create(ctx, a); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate id: %v", err)
	}
	dupName := mustStored(t, "rb_b", "p_1")
	if _, err := m.Create(ctx, dupName); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate name in scope: %v", err)
	}
	// the same name in another scope is fine
	if _, err := m.Create(ctx, mustStored(t, "rb_c", "p_2")); err != nil {
		t.Fatalf("same name other scope: %v", err)
	}

	// stored copies are isolated from callers
	got.Parameters[0].Name = "TAMPERED"
	again, _ := m.Get(ctx, "rb_a")
	if again.Parameters[0].Name != "SERVICE" {
		t.Fatalf("repository state aliased: %v", again.Parameters[0].Name)
	}

	again.Description = "updated"
	up, err := m.Update(ctx, again)
	if err != nil || up.Version != 2 {
		t.Fatalf("Update: %v %+v", err, up)
	}
	if _, err := m.Update(ctx, again); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale update: %v", err)
	}
	moved := up
	moved.ScopeId = "p_2"
	if _, err := m.Update(ctx, moved); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("scope change: %v", err)
	}
	bad := up
	bad.SourceCommitSHA = "main"
	if _, err := m.Update(ctx, bad); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("floating ref on update: %v", err)
	}
	if _, err := m.Update(ctx, StoredDefinition{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty update: %v", err)
	}

	l, err := m.List(ctx, "p_1")
	if err != nil || len(l) != 1 || l[0].Id != "rb_a" {
		t.Fatalf("List: %v %+v", err, l)
	}
	if err := m.Delete(ctx, "rb_a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := m.Delete(ctx, "rb_a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if _, err := m.Get(ctx, "rb_a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete: %v", err)
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := m.Get(cctx, "x"); err == nil {
		t.Fatal("cancelled context accepted")
	}
}
