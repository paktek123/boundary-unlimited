// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"sync"

	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
)

var (
	recFactoryMu sync.RWMutex
	recFactory   RecordingFactory
)

// InstallRecordingFactory installs the RecordingFactory the registered ssh
// handler uses for sessions whose input enables recording. It is called at
// worker startup once the scratch store and storage are available. Passing nil
// uninstalls it, after which recorded sessions are refused.
func InstallRecordingFactory(f RecordingFactory) {
	recFactoryMu.Lock()
	defer recFactoryMu.Unlock()
	if isNilValue(f) {
		f = nil
	}
	recFactory = f
}

func installedRecordingFactory() RecordingFactory {
	recFactoryMu.RLock()
	defer recFactoryMu.RUnlock()
	return recFactory
}

// RecoverScratch registers recordings left in the scratch store by a previous
// worker process (see scratch.Store.Recover). It never deletes anything and
// is to be called once at worker startup, before sessions are accepted.
func RecoverScratch(ctx context.Context, s *scratch.Store) ([]scratch.Orphan, error) {
	const op = "ssh.RecoverScratch"
	if s == nil {
		return nil, errNew(ctx, op, "missing scratch store")
	}
	return s.Recover()
}
