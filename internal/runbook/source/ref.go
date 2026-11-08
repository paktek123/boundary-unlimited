// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package source

import (
	"errors"
	"strings"
)

// ErrInvalidRef is returned for anything but a full lowercase 40-hex commit SHA.
var ErrInvalidRef = errors.New("source: ref must be a full 40-character lowercase hex commit SHA")

// ErrInvalidPath is returned for a runbook file path that is not a plain
// relative path inside the repository.
var ErrInvalidPath = errors.New("source: invalid runbook file path")

// ValidateSHA accepts only a full 40-character lowercase hex commit SHA.
// Branches, tags, short SHAs, uppercase or mixed-case hex, "HEAD", refs such as
// "refs/heads/x" and revision expressions ("a~1", "a^") are all rejected. The
// error never echoes the input.
func ValidateSHA(s string) error {
	if len(s) != 40 {
		return ErrInvalidRef
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ErrInvalidRef
		}
	}
	return nil
}

// MaxPathLen bounds a runbook file path.
const MaxPathLen = 512

// ValidatePath accepts only a clean, relative, forward-slash path that names a
// file inside the repository. It rejects empty and absolute paths, "." and
// ".." elements, backslashes, NUL/control characters, and any element that is
// ".git", ".gitmodules", ".gitattributes" or a hooks directory (submodule and
// hook paths). Symlinks cannot be detected from a path alone; fetchers must
// refuse them (see the package contract).
func ValidatePath(p string) error {
	if p == "" || len(p) > MaxPathLen || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return ErrInvalidPath
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidPath
		}
	}
	for _, el := range strings.Split(p, "/") {
		switch strings.ToLower(el) {
		case "", ".", "..", ".git", ".gitmodules", ".gitattributes", "hooks":
			return ErrInvalidPath
		}
		if len(el) >= 4 && strings.EqualFold(el[:4], ".git") && strings.Trim(strings.ToLower(el), ". ") == "git" {
			return ErrInvalidPath
		}
	}
	return nil
}
