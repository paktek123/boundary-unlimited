// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package scratch

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// filesDir holds the named files of a recording (for example the files of a
// BSR container) below the recording's directory. It is separate from the
// single data file so the fixed marker and data names cannot be shadowed.
const filesDir = "files"

// ErrInvalidFileName is returned for names that are not a confined, relative,
// slash separated path.
var ErrInvalidFileName = errors.New("scratch: invalid file name")

var fileComponentRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// FilePath returns the on-disk path of the named file of a recording after
// validating name: it must be relative, use "/" separators and every
// component must be a plain name (no empty, "." or ".." components).
func (s *Store) FilePath(sessionID, name string) (string, error) {
	d, err := s.dir(sessionID)
	if err != nil {
		return "", err
	}
	if name == "" || strings.HasPrefix(name, "/") {
		return "", ErrInvalidFileName
	}
	parts := strings.Split(name, "/")
	for _, p := range parts {
		if p == "." || p == ".." || !fileComponentRe.MatchString(p) {
			return "", ErrInvalidFileName
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.recs[sessionID]; !ok {
		return "", ErrNotFound
	}
	return filepath.Join(append([]string{d, filesDir}, parts...)...), nil
}

// WriteFile appends p to the named file of the recording, creating the file
// and its parent directories if needed. Every byte is accounted against the
// quota exactly as for Write: a write that would exceed the quota writes
// nothing, marks the recording incomplete and returns ErrQuotaExceeded.
func (s *Store) WriteFile(sessionID, name string, p []byte) (int, error) {
	path, err := s.FilePath(sessionID, name)
	if err != nil {
		return 0, err
	}
	d, _ := s.dir(sessionID)
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
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return 0, fmt.Errorf("scratch: create file dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return 0, fmt.Errorf("scratch: open file: %w", err)
	}
	w, werr := f.Write(p)
	cerr := f.Close()
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
		return w, fmt.Errorf("scratch: write file: %w", errors.Join(werr, cerr))
	}
	return w, nil
}

// filesSize returns the total size of the regular files below the recording's
// files directory, used by Recover to account for them.
func filesSize(d string) int64 {
	var size int64
	_ = filepath.WalkDir(filepath.Join(d, filesDir), func(_ string, e fs.DirEntry, err error) error {
		if err != nil || !e.Type().IsRegular() {
			return nil
		}
		if fi, err := e.Info(); err == nil {
			size += fi.Size()
		}
		return nil
	})
	return size
}
