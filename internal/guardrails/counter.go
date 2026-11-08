// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package guardrails

import (
	"errors"
	"sync"
)

// Bounds for the number of blocked commands after which a session ends.
const (
	MinBlocksBeforeTerminate     = 1
	MaxBlocksBeforeTerminate     = 20
	DefaultBlocksBeforeTerminate = 5
)

// ErrInvalidBlockLimit is returned for a limit outside 1..20.
var ErrInvalidBlockLimit = errors.New("guardrails: block limit must be between 1 and 20")

// BlockCounter counts blocked commands for one session. It cannot be reset.
type BlockCounter struct {
	mu    sync.Mutex
	limit int
	count int
}

// NewBlockCounter returns a counter that signals termination on the nth block.
func NewBlockCounter(n int) (*BlockCounter, error) {
	if n < MinBlocksBeforeTerminate || n > MaxBlocksBeforeTerminate {
		return nil, ErrInvalidBlockLimit
	}
	return &BlockCounter{limit: n}, nil
}

// Record counts one blocked command and reports whether the session must be
// terminated: true on the nth block and on every later call.
func (b *BlockCounter) Record() (terminate bool) {
	if b == nil {
		return true // fail closed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.count < b.limit {
		b.count++
	}
	return b.count >= b.limit
}

// Count returns the number of blocks recorded so far.
func (b *BlockCounter) Count() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count
}
