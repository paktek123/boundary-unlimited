// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package source

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const goodSHA = "0123456789abcdef0123456789abcdef01234567"

func TestValidateSHA(t *testing.T) {
	for _, bad := range []string{"", "main", "v1.2.3", "abc1234", "HEAD", "refs/heads/main", "0123456789ABCDEF0123456789abcdef01234567", "0123456789abcdef0123456789abcdef0123456", goodSHA + "0", "0123456789abcdef0123456789abcdef0123456g", "0123456789abcdef0123456789abcdef01234567\n"} {
		if err := ValidateSHA(bad); !errors.Is(err, ErrInvalidRef) {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := ValidateSHA(goodSHA); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePath(t *testing.T) {
	for _, bad := range []string{"", "/abs.sh", "../x", "a/../b", "a//b", "./a", "a/.", ".git/config", "a/.git/x", ".gitmodules", "a/.GITMODULES", "hooks/pre-commit", "a\\b", "a\x00b", "a\nb", strings.Repeat("a", MaxPathLen+1)} {
		if err := ValidatePath(bad); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, ok := range []string{"runbooks/restart.sh", "a.sh"} {
		if err := ValidatePath(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
}

func TestPinVerify(t *testing.T) {
	script := []byte("echo hi\n")
	pin, err := NewPin(goodSHA, script)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pin, script); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pin, []byte("echo bye\n")); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("mismatch not refused: %v", err)
	}
	for _, p := range []Pin{{}, {SHA: goodSHA}, {SHA: goodSHA, ScriptSHA256: "zz"}, {SHA: "main", ScriptSHA256: pin.ScriptSHA256}} {
		if err := Verify(p, script); err == nil {
			t.Errorf("invalid pin %+v verified", p)
		}
	}
	if _, err := NewPin("main", script); err == nil {
		t.Fatal("NewPin accepted floating ref")
	}
}

func TestGet(t *testing.T) {
	ctx := context.Background()
	f := &FakeFetcher{}
	f.Add(goodSHA, "rb/a.sh", []byte("echo hi\n"))
	b, pin, err := Get(ctx, f, "https://example.invalid/r.git", goodSHA, "rb/a.sh", Limits{})
	if err != nil || string(b) != "echo hi\n" || pin.SHA != goodSHA {
		t.Fatalf("Get: %v %v", pin, err)
	}

	f.Add(goodSHA, "rb/big.sh", make([]byte, 101))
	f.Add(goodSHA, "rb/empty.sh", nil)
	tests := []struct {
		name, sha, path string
		lim             Limits
		fx              *FakeFetcher
	}{
		{"branch", "main", "rb/a.sh", Limits{}, f},
		{"traversal", goodSHA, "../a.sh", Limits{}, f},
		{"oversize", goodSHA, "rb/big.sh", Limits{MaxScriptBytes: 100}, f},
		{"empty", goodSHA, "rb/empty.sh", Limits{}, f},
		{"missing", goodSHA, "rb/none.sh", Limits{}, f},
		{"fetcher error", goodSHA, "rb/a.sh", Limits{}, &FakeFetcher{Err: errors.New("boom")}},
		{"too many files", goodSHA, "rb/a.sh", Limits{MaxFiles: 5}, func() *FakeFetcher {
			g := &FakeFetcher{Count: 6}
			g.Add(goodSHA, "rb/a.sh", []byte("x"))
			return g
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, pin, err := Get(ctx, tt.fx, "https://example.invalid/r.git", tt.sha, tt.path, tt.lim)
			if err == nil || b != nil || pin != (Pin{}) {
				t.Fatalf("expected fail-closed rejection, got %v", err)
			}
		})
	}
	if _, _, err := Get(ctx, nil, "u", goodSHA, "a", Limits{}); err == nil {
		t.Fatal("nil fetcher accepted")
	}
	if _, _, err := Get(ctx, f, "", goodSHA, "rb/a.sh", Limits{}); err == nil {
		t.Fatal("empty repo URL accepted")
	}
}

func TestInvalidInputNeverReachesFetcher(t *testing.T) {
	f := &FakeFetcher{}
	_, _, _ = Get(context.Background(), f, "u", "main", "a.sh", Limits{})
	_, _, _ = Get(context.Background(), f, "u", goodSHA, "../a", Limits{})
	if f.Calls != 0 {
		t.Fatalf("fetcher called %d times", f.Calls)
	}
}

func TestFakeFetcherConformance(t *testing.T) {
	f := &FakeFetcher{}
	f.Add(goodSHA, "rb/a.sh", []byte("echo hi\n"))
	RunFetcherConformance(t, f, "https://example.invalid/r.git", goodSHA, "rb/a.sh", []byte("echo hi\n"))
}
