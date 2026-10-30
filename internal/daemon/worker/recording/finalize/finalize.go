// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package finalize completes a session recording: it finishes the recording
// on scratch storage, submits it for upload and, only after a verified
// upload, removes the scratch data (see the "Failure modes" section of
// docs/rfc/ssh-session-recording.md). Scratch data is never discarded when
// finishing or uploading fails, so a recording is never silently lost.
//
// The package is a standalone library and is not wired into the worker.
package finalize

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
)

// Scratch is the subset of scratch.Store used by the Finalizer.
type Scratch interface {
	Finish(sessionID string) error
	Path(sessionID string) (string, error)
	MarkUploaded(sessionID string) error
	Discard(sessionID string) error
}

// Submitter validates and uploads a recording, typically an *upload.Manager.
type Submitter interface {
	Submit(ctx context.Context, rec upload.Recording) upload.Result
}

// Finalizer completes recordings. It is safe for concurrent use.
type Finalizer struct {
	scratch Scratch
	sub     Submitter

	mu   sync.Mutex
	done map[string]upload.Result
}

// New creates a Finalizer. Both collaborators are required.
func New(s Scratch, sub Submitter) (*Finalizer, error) {
	switch {
	case s == nil:
		return nil, errors.New("finalize: scratch is required")
	case sub == nil:
		return nil, errors.New("finalize: submitter is required")
	}
	return &Finalizer{scratch: s, sub: sub, done: map[string]upload.Result{}}, nil
}

// Finalize finishes, uploads and cleans up the recording for sessionID.
//
// A Finish error (including scratch.ErrIncomplete for an incomplete
// recording) is returned without calling Submit and without touching the
// scratch data. When Submit reports anything other than StatusUploaded the
// scratch data is kept and the Result is returned, with a non-nil error, for
// the caller to report. After a successful upload a repeated call returns the
// original Result without uploading again.
func (f *Finalizer) Finalize(ctx context.Context, sessionID string) (upload.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if res, ok := f.done[sessionID]; ok {
		return res, nil
	}
	if err := f.scratch.Finish(sessionID); err != nil {
		return upload.Result{}, fmt.Errorf("finalize: finish recording %q: %w", sessionID, err)
	}
	dir, err := f.scratch.Path(sessionID)
	if err != nil {
		return upload.Result{}, fmt.Errorf("finalize: locate recording %q: %w", sessionID, err)
	}
	res := f.sub.Submit(ctx, upload.Recording{SessionID: sessionID, Dir: dir})
	if res.Status != upload.StatusUploaded {
		err := res.Err
		if err == nil {
			err = fmt.Errorf("upload status %d", res.Status)
		}
		return res, fmt.Errorf("finalize: recording %q not uploaded, scratch data kept: %w", sessionID, err)
	}
	// The upload is verified: only now may the scratch data go.
	if err := f.scratch.MarkUploaded(sessionID); err != nil {
		return res, fmt.Errorf("finalize: mark recording %q uploaded: %w", sessionID, err)
	}
	if err := f.scratch.Discard(sessionID); err != nil && !errors.Is(err, scratch.ErrNotFound) {
		return res, fmt.Errorf("finalize: discard recording %q: %w", sessionID, err)
	}
	f.done[sessionID] = res
	return res, nil
}
