// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package source

import (
	"context"
	"testing"
)

// RunFetcherConformance checks the behaviour every Fetcher must have through
// Get: invalid refs and paths never reach the fetcher, and a returned script
// verifies against its pin. known must be a sha/path/content that f serves.
func RunFetcherConformance(t *testing.T, f Fetcher, repoURL, sha, path string, content []byte) {
	t.Helper()
	ctx := context.Background()
	for _, bad := range []string{"main", "v1.0.0", "abc1234", "HEAD", "refs/heads/main", sha[:39], sha + "0", "ABCDEF" + sha[6:]} {
		if _, _, err := Get(ctx, f, repoURL, bad, path, Limits{}); err == nil {
			t.Errorf("floating or malformed ref %q accepted", bad)
		}
	}
	for _, bad := range []string{"", "../x.sh", "/etc/passwd", "a/../../x", ".git/config", ".gitmodules", "x\\y"} {
		if _, _, err := Get(ctx, f, repoURL, sha, bad, Limits{}); err == nil {
			t.Errorf("bad path %q accepted", bad)
		}
	}
	b, pin, err := Get(ctx, f, repoURL, sha, path, Limits{})
	if err != nil {
		t.Fatalf("known file: %v", err)
	}
	if err := Verify(pin, b); err != nil {
		t.Errorf("fresh pin does not verify: %v", err)
	}
	if err := Verify(pin, append(b, ' ')); err == nil {
		t.Error("modified script verified")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := Get(cctx, f, repoURL, sha, path, Limits{}); err == nil {
		t.Error("cancelled context did not fail")
	}
	_ = content
}
