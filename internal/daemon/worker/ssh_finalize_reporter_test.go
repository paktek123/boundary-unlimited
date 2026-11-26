// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSHFinalizeReporter(t *testing.T) {
	const canary = "/var/secret-bucket/path-canary"
	type call struct {
		msg  string
		args []any
	}
	var calls []call
	r := sshFinalizeReporter{write: func(_ context.Context, _ event.Op, msg string, args ...any) {
		calls = append(calls, call{msg, args})
	}}

	r.RecordingFinalized(context.Background(), "s_123", upload.Result{Attempts: 1}, nil)
	r.RecordingFinalized(context.Background(), "s_456", upload.Result{Attempts: 3, Err: errors.New(canary)}, errors.New(canary))
	require.Len(t, calls, 2)
	assert.Equal(t, "ssh recording finalized", calls[0].msg)
	assert.Equal(t, "ssh recording finalization failed", calls[1].msg)
	for _, c := range calls {
		assert.NotContains(t, fmt.Sprint(c.msg, c.args), canary)
	}

	// A reporter without a writer must not panic.
	sshFinalizeReporter{}.RecordingFinalized(context.Background(), "s_1", upload.Result{}, errors.New("x"))
}
