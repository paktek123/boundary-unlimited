// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checkSource returns descriptions of forbidden host key verification
// patterns found in src: ssh.InsecureIgnoreHostKey, a ClientConfig literal
// without HostKeyCallback, and a nil HostKeyCallback.
func checkSource(t *testing.T, filename string, src any) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	require.NoError(t, err)

	var found []string
	report := func(p token.Pos, msg string) {
		found = append(found, fset.Position(p).String()+": "+msg)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if x.Sel.Name == "InsecureIgnoreHostKey" {
				report(x.Pos(), "InsecureIgnoreHostKey is forbidden")
			}
		case *ast.CompositeLit:
			if !isClientConfig(x.Type) {
				return true
			}
			hasCallback := false
			for _, el := range x.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "HostKeyCallback" {
					hasCallback = true
					if v, ok := kv.Value.(*ast.Ident); ok && v.Name == "nil" {
						report(kv.Pos(), "nil HostKeyCallback is forbidden")
					}
				}
			}
			if !hasCallback {
				report(x.Pos(), "ClientConfig without HostKeyCallback is forbidden")
			}
		case *ast.AssignStmt:
			for i, l := range x.Lhs {
				sel, ok := l.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "HostKeyCallback" || i >= len(x.Rhs) {
					continue
				}
				if v, ok := x.Rhs[i].(*ast.Ident); ok && v.Name == "nil" {
					report(x.Pos(), "nil HostKeyCallback is forbidden")
				}
			}
		}
		return true
	})
	return found
}

func isClientConfig(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		return t.Sel.Name == "ClientConfig"
	case *ast.Ident:
		return t.Name == "ClientConfig"
	}
	return false
}

func TestNoInsecureHostKeyHandling(t *testing.T) {
	root := "."
	if _, err := os.Stat(root); err != nil {
		t.Skip("directory does not exist")
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, v := range checkSource(t, path, nil) {
			t.Error(v)
		}
		return nil
	})
	require.NoError(t, err)
}

func TestCheckSourceSelfTest(t *testing.T) {
	const pre = "package x\nimport \"golang.org/x/crypto/ssh\"\nvar _ = "
	tests := []struct {
		name string
		src  string
		want int
	}{
		{"insecure ignore", pre + "ssh.InsecureIgnoreHostKey()\n", 1},
		{"missing callback", pre + "&ssh.ClientConfig{User: \"u\"}\n", 1},
		{"nil callback", pre + "&ssh.ClientConfig{HostKeyCallback: nil}\n", 1},
		{"assigned nil", "package x\nimport \"golang.org/x/crypto/ssh\"\nfunc f(c *ssh.ClientConfig) { c.HostKeyCallback = nil }\n", 1},
		{"ok", pre + "&ssh.ClientConfig{HostKeyCallback: cb}\nvar cb ssh.HostKeyCallback\n", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Len(t, checkSource(t, "snippet.go", tt.src), tt.want)
		})
	}
}
