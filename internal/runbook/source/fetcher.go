// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package source

import (
	"context"
	"errors"
	"fmt"
)

// Default limits.
const (
	DefaultMaxScriptBytes = 1 << 20
	DefaultMaxFiles       = 10000
)

// Limits bound what a fetch may touch.
type Limits struct {
	MaxScriptBytes int // zero means DefaultMaxScriptBytes
	MaxFiles       int // zero means DefaultMaxFiles; applies to the tree walked
}

func (l Limits) withDefaults() Limits {
	if l.MaxScriptBytes <= 0 {
		l.MaxScriptBytes = DefaultMaxScriptBytes
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = DefaultMaxFiles
	}
	return l
}

// Fetcher retrieves the bytes of one file at one commit. See the package
// documentation for the contract real implementations must meet.
type Fetcher interface {
	Fetch(ctx context.Context, repoURL, sha, path string) ([]byte, error)
}

// TreeCounter is optionally implemented by a Fetcher that can report how many
// files the commit's tree holds, so Get can enforce Limits.MaxFiles.
type TreeCounter interface {
	FileCount(ctx context.Context, repoURL, sha string) (int, error)
}

// Get validates sha and path, fetches the file through f, enforces limits and
// returns the bytes with the Pin to record. It fails closed: any fetcher error
// or limit violation returns no script. Errors do not include script content.
func Get(ctx context.Context, f Fetcher, repoURL, sha, path string, lim Limits) ([]byte, Pin, error) {
	lim = lim.withDefaults()
	if f == nil {
		return nil, Pin{}, errors.New("source: nil fetcher")
	}
	if repoURL == "" {
		return nil, Pin{}, errors.New("source: empty repository URL")
	}
	if err := ValidateSHA(sha); err != nil {
		return nil, Pin{}, err
	}
	if err := ValidatePath(path); err != nil {
		return nil, Pin{}, err
	}
	if tc, ok := f.(TreeCounter); ok {
		n, err := tc.FileCount(ctx, repoURL, sha)
		if err != nil {
			return nil, Pin{}, fmt.Errorf("source: counting files: %w", err)
		}
		if n > lim.MaxFiles {
			return nil, Pin{}, errors.New("source: repository has too many files")
		}
	}
	b, err := f.Fetch(ctx, repoURL, sha, path)
	if err != nil {
		return nil, Pin{}, fmt.Errorf("source: fetch failed: %w", err)
	}
	if len(b) == 0 {
		return nil, Pin{}, errors.New("source: empty script")
	}
	if len(b) > lim.MaxScriptBytes {
		return nil, Pin{}, errors.New("source: script too large")
	}
	pin, err := NewPin(sha, b)
	if err != nil {
		return nil, Pin{}, err
	}
	return b, pin, nil
}
