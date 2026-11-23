// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"errors"
	"fmt"
)

// ErrRecordingBucketUnavailable is returned when no storage bucket can be
// resolved for a session. It is a fixed class: it never carries bucket names,
// credentials or the text of the underlying error.
var ErrRecordingBucketUnavailable = errors.New("worker: recording bucket unavailable")

// ErrNoRecordingBucket is what a SessionBucketLookup returns when the session
// has no storage bucket.
var ErrNoRecordingBucket = errors.New("worker: session has no storage bucket")

// SessionBucketRef is the controller-provided description of the storage
// bucket for one session. Secret is held in memory only; the type redacts it
// from any formatting so it cannot reach logs or events by accident.
type SessionBucketRef struct {
	BucketId string
	Secret   []byte
}

// String redacts the credential.
func (r SessionBucketRef) String() string { return "SessionBucketRef{redacted}" }

// GoString redacts the credential for %#v.
func (r SessionBucketRef) GoString() string { return r.String() }

// SessionBucketLookup returns the bucket reference the controller supplied
// for the session. It returns ErrNoRecordingBucket when there is none.
type SessionBucketLookup func(ctx context.Context, sessionId string) (SessionBucketRef, error)

// SessionBucketOpener opens a connection to the bucket described by ref.
type SessionBucketOpener func(ctx context.Context, ref SessionBucketRef) (RecordingBucketSession, error)

// sessionBucketSource implements RecordingBucketSource over controller data.
// It fails closed: any missing piece yields ErrRecordingBucketUnavailable.
type sessionBucketSource struct {
	lookup SessionBucketLookup
	open   SessionBucketOpener
}

var _ RecordingBucketSource = (*sessionBucketSource)(nil)

// NewSessionBucketSource builds a RecordingBucketSource. Nil dependencies
// produce a source that refuses every session.
func NewSessionBucketSource(lookup SessionBucketLookup, open SessionBucketOpener) RecordingBucketSource {
	return &sessionBucketSource{lookup: lookup, open: open}
}

func (s *sessionBucketSource) Open(ctx context.Context, sessionId string) (RecordingBucketSession, error) {
	if s == nil || s.lookup == nil || s.open == nil || sessionId == "" {
		return nil, ErrRecordingBucketUnavailable
	}
	ref, err := s.lookup(ctx, sessionId)
	if err != nil || ref.BucketId == "" {
		return nil, ErrRecordingBucketUnavailable
	}
	bs, err := s.open(ctx, ref)
	if err != nil || isNilSession(bs) {
		return nil, fmt.Errorf("%w", ErrRecordingBucketUnavailable)
	}
	return bs, nil
}
