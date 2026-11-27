// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package main

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestKubernetesTargetNotRegistered guards the enforcement-first rule of
// #336/#26: the kubernetes target subtype and its handler must not be linked
// into the boundary binary until the worker relay can enforce kubernetes
// sessions end to end. Whoever registers them must update this test in the
// same change, which makes the enabling step explicit in review.
func TestKubernetesTargetNotRegistered(t *testing.T) {
	fset := token.NewFileSet()
	// Every non-test file of package main, so registration through any file is caught.
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		require.NoError(t, err)
		for _, imp := range f.Imports {
			require.NotContains(t, strings.ToLower(imp.Path.Value), "kubernetes", "kubernetes is linked in %s: %s", name, imp.Path.Value)
		}
	}
}
