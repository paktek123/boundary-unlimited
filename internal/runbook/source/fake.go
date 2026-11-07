// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package source

import (
	"context"
	"errors"
	"sync"
)

// FakeFetcher is an in-memory Fetcher for tests. It is keyed by (sha, path);
// repoURL is recorded but not interpreted.
type FakeFetcher struct {
	mu    sync.Mutex
	Files map[[2]string][]byte
	Count int   // value reported by FileCount
	Err   error // returned by Fetch when set
	Calls int
}

// Add registers a file.
func (f *FakeFetcher) Add(sha, path string, content []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Files == nil {
		f.Files = map[[2]string][]byte{}
	}
	f.Files[[2]string{sha, path}] = append([]byte(nil), content...)
}

// Fetch implements Fetcher.
func (f *FakeFetcher) Fetch(ctx context.Context, _, sha, path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.Err != nil {
		return nil, f.Err
	}
	b, ok := f.Files[[2]string{sha, path}]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), b...), nil
}

// FileCount implements TreeCounter.
func (f *FakeFetcher) FileCount(context.Context, string, string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Count, nil
}
