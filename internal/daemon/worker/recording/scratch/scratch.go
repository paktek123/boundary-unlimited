// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package scratch implements a bounded, worker-local scratch area for
// in-progress session recordings, as described in the "Storage" section of
// docs/rfc/ssh-session-recording.md. The quota is a hard limit that fails
// closed: callers must refuse to start (or must terminate) a session when
// the store reports ErrQuotaExceeded, so no session continues unrecorded.
//
// The package is a standalone library and is not wired into the worker.
package scratch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
)

const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600

	dataFile       = "data"
	incompleteFile = "incomplete"
	finishedFile   = "finished"
)

var (
	// ErrQuotaExceeded is returned when the quota cannot accommodate a
	// reservation or a write.
	ErrQuotaExceeded = errors.New("scratch: quota exceeded")
	// ErrInvalidSessionID is returned for session ids that are not safe to
	// use as a path component.
	ErrInvalidSessionID = errors.New("scratch: invalid session id")
	// ErrNotFound is returned when the recording is not known to the store.
	ErrNotFound = errors.New("scratch: recording not found")
	// ErrExists is returned when the recording already exists.
	ErrExists = errors.New("scratch: recording already exists")
	// ErrIncomplete is returned when an operation requires a complete
	// recording but it has been marked incomplete.
	ErrIncomplete = errors.New("scratch: recording is incomplete")
	// ErrNotFinished is returned by MarkUploaded for a recording that has
	// not been finished.
	ErrNotFinished = errors.New("scratch: recording is not finished")
)

var sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

type state int

const (
	stateActive state = iota
	stateFinished
	stateIncomplete
)

type recording struct {
	size     int64
	reserved int64
	state    state
}

// Store is a bounded scratch area. It is safe for concurrent use.
type Store struct {
	root  string
	quota int64

	mu   sync.Mutex
	used int64 // bytes written plus outstanding reservations
	recs map[string]*recording
}

// New creates a Store rooted at root (created with mode 0700 if missing) with
// the given quota in bytes. Existing recordings are not loaded: call Recover.
func New(root string, quota int64) (*Store, error) {
	if root == "" {
		return nil, errors.New("scratch: root is required")
	}
	if quota <= 0 {
		return nil, errors.New("scratch: quota must be positive")
	}
	if err := os.MkdirAll(root, dirMode); err != nil {
		return nil, fmt.Errorf("scratch: create root: %w", err)
	}
	if err := os.Chmod(root, dirMode); err != nil {
		return nil, fmt.Errorf("scratch: chmod root: %w", err)
	}
	return &Store{root: root, quota: quota, recs: map[string]*recording{}}, nil
}

func (s *Store) dir(sessionID string) (string, error) {
	if !sessionIDRe.MatchString(sessionID) {
		return "", ErrInvalidSessionID
	}
	return filepath.Join(s.root, sessionID), nil
}

// Reserve creates the recording and reserves capacity bytes for it. It fails
// with ErrQuotaExceeded when the quota cannot cover the reservation so the
// caller can refuse to start the session.
func (s *Store) Reserve(sessionID string, capacity int64) error {
	d, err := s.dir(sessionID)
	if err != nil {
		return err
	}
	if capacity < 0 {
		return errors.New("scratch: negative reservation")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.recs[sessionID]; ok {
		return ErrExists
	}
	if capacity > s.quota-s.used {
		return ErrQuotaExceeded
	}
	if err := os.Mkdir(d, dirMode); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return fmt.Errorf("scratch: create recording dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(d, dataFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileMode)
	if err != nil {
		_ = os.RemoveAll(d)
		return fmt.Errorf("scratch: create data file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.RemoveAll(d)
		return fmt.Errorf("scratch: close data file: %w", err)
	}
	s.recs[sessionID] = &recording{reserved: capacity}
	s.used += capacity
	return nil
}

// Write appends p to the recording. A write that would exceed the quota
// writes nothing, marks the recording incomplete and returns
// ErrQuotaExceeded; data is never silently dropped.
func (s *Store) Write(sessionID string, p []byte) (int, error) {
	d, err := s.dir(sessionID)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[sessionID]
	if !ok {
		return 0, ErrNotFound
	}
	switch r.state {
	case stateIncomplete:
		return 0, ErrIncomplete
	case stateFinished:
		return 0, errors.New("scratch: recording is finished")
	}
	n := int64(len(p))
	// Writes first consume the recording's own reservation, then the
	// remaining shared capacity.
	extra := n - r.reserved
	if extra < 0 {
		extra = 0
	}
	if extra > s.quota-s.used {
		if err := s.markIncompleteLocked(d, r); err != nil {
			return 0, errors.Join(ErrQuotaExceeded, err)
		}
		return 0, ErrQuotaExceeded
	}
	f, err := os.OpenFile(filepath.Join(d, dataFile), os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return 0, fmt.Errorf("scratch: open data file: %w", err)
	}
	w, werr := f.Write(p)
	cerr := f.Close()
	// Account for whatever reached the file, even on error.
	consumed := int64(w)
	fromRes := consumed
	if fromRes > r.reserved {
		fromRes = r.reserved
	}
	r.reserved -= fromRes
	s.used += consumed - fromRes
	r.size += consumed
	if werr != nil || cerr != nil {
		_ = s.markIncompleteLocked(d, r)
		return w, fmt.Errorf("scratch: write: %w", errors.Join(werr, cerr))
	}
	return w, nil
}

func (s *Store) markIncompleteLocked(d string, r *recording) error {
	if r.state != stateIncomplete {
		if err := writeMarker(filepath.Join(d, incompleteFile)); err != nil {
			return err
		}
		r.state = stateIncomplete
	}
	return nil
}

func writeMarker(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return fmt.Errorf("scratch: write marker: %w", err)
	}
	return f.Close()
}

// syncPath fsyncs the file or directory at path.
func syncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("scratch: open for sync: %w", err)
	}
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(serr, cerr); err != nil {
		return fmt.Errorf("scratch: sync: %w", err)
	}
	return nil
}

// Finish marks the recording as finished and releases unused reservation.
// An incomplete recording cannot be finished.
func (s *Store) Finish(sessionID string) error {
	d, err := s.dir(sessionID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[sessionID]
	if !ok {
		return ErrNotFound
	}
	if r.state == stateIncomplete {
		return ErrIncomplete
	}
	// Make the data durable before the marker, and the marker durable before
	// reporting success, so that after a crash Recover never sees Finished for
	// truncated data.
	if err := syncPath(filepath.Join(d, dataFile)); err != nil {
		return err
	}
	if err := writeMarker(filepath.Join(d, finishedFile)); err != nil {
		return err
	}
	if err := syncPath(filepath.Join(d, finishedFile)); err != nil {
		return err
	}
	if err := syncPath(d); err != nil {
		return err
	}
	s.used -= r.reserved
	r.reserved = 0
	r.state = stateFinished
	return nil
}

// MarkUploaded removes the scratch files of a finished recording. Call it
// only after the upload has been verified.
func (s *Store) MarkUploaded(sessionID string) error {
	d, err := s.dir(sessionID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[sessionID]
	if !ok {
		return ErrNotFound
	}
	if r.state != stateFinished {
		return ErrNotFinished
	}
	if err := os.RemoveAll(d); err != nil {
		return fmt.Errorf("scratch: remove recording: %w", err)
	}
	s.used -= r.size + r.reserved
	delete(s.recs, sessionID)
	return nil
}

// Discard removes the recording regardless of its state. It is an explicit
// operator/caller decision; the store never discards on its own.
func (s *Store) Discard(sessionID string) error {
	d, err := s.dir(sessionID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[sessionID]
	if !ok {
		return ErrNotFound
	}
	if err := os.RemoveAll(d); err != nil {
		return fmt.Errorf("scratch: remove recording: %w", err)
	}
	s.used -= r.size + r.reserved
	delete(s.recs, sessionID)
	return nil
}

// Used returns the bytes currently accounted against the quota.
func (s *Store) Used() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
}

// Path returns the directory holding the recording's files.
func (s *Store) Path(sessionID string) (string, error) {
	d, err := s.dir(sessionID)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.recs[sessionID]; !ok {
		return "", ErrNotFound
	}
	return d, nil
}

// Orphan describes a recording found on disk after a restart.
type Orphan struct {
	SessionID string
	Size      int64
	// Finished is true when the recording had been finished (and so was
	// awaiting upload) when the worker stopped.
	Finished bool
}

// Recover scans the root for recordings left behind by a previous process,
// registers them with the store (accounting their size against the quota)
// and marks any that were not finished as incomplete. It never deletes
// anything. Entries with invalid names are ignored. Orphans are returned
// sorted by session id.
func (s *Store) Recover() ([]Orphan, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("scratch: read root: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Orphan
	for _, e := range entries {
		id := e.Name()
		if !e.IsDir() || !sessionIDRe.MatchString(id) {
			continue
		}
		if _, ok := s.recs[id]; ok {
			continue
		}
		d := filepath.Join(s.root, id)
		var size int64
		if fi, err := os.Lstat(filepath.Join(d, dataFile)); err == nil && fi.Mode().IsRegular() {
			size = fi.Size()
		}
		size += filesSize(d)
		r := &recording{size: size, state: stateIncomplete}
		_, ferr := os.Lstat(filepath.Join(d, finishedFile))
		_, ierr := os.Lstat(filepath.Join(d, incompleteFile))
		finished := ferr == nil && ierr != nil
		if finished {
			r.state = stateFinished
		} else if err := writeMarker(filepath.Join(d, incompleteFile)); err != nil {
			return out, err
		}
		s.recs[id] = r
		s.used += size
		out = append(out, Orphan{SessionID: id, Size: size, Finished: finished})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SessionID < out[j].SessionID })
	return out, nil
}
