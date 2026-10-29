// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package finalize

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
)

// Recoverer lists recordings left behind by a previous process, typically a
// *scratch.Store. Implementations must mark unfinished recordings incomplete,
// as scratch.Store.Recover does.
type Recoverer interface {
	Recover() ([]scratch.Orphan, error)
}

// Runner finalises one recording, typically a *Finalizer.
type Runner interface {
	Finalize(ctx context.Context, sessionID string) (upload.Result, error)
}

// Recover runs at worker start. It lists the orphaned recordings and pushes
// each through the finalisation pipeline. Orphans that were not finished
// when the previous process stopped are incomplete (the store writes the
// marker during Recover, before anything is uploaded); finalisation refuses
// them with scratch.ErrIncomplete and their data is kept, never deleted.
//
// A failure on one orphan does not stop the others; all errors are joined
// and returned. If ctx ends, Recover stops before the next orphan and
// includes ctx.Err() in the result; nothing is discarded.
func Recover(ctx context.Context, store Recoverer, runner Runner) error {
	if store == nil {
		return errors.New("finalize: recoverer is required")
	}
	if runner == nil {
		return errors.New("finalize: runner is required")
	}
	orphans, err := store.Recover()
	if err != nil {
		return fmt.Errorf("finalize: recover orphans: %w", err)
	}
	var errs []error
	for _, o := range orphans {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		if _, err := runner.Finalize(ctx, o.SessionID); err != nil {
			errs = append(errs, fmt.Errorf("finalize: orphan %q: %w", o.SessionID, err))
		}
	}
	return errors.Join(errs...)
}
