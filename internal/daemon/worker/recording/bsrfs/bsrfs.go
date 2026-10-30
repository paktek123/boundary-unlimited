// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package bsrfs adapts the bounded scratch store to the storage.FS interface
// used by internal/bsr, so BSR containers are written through the scratch
// store and every byte counts against its quota. A write beyond the quota
// returns scratch.ErrQuotaExceeded (never a silent truncation) so the error
// propagates to the recorder. All names are confined to the recording's
// scratch directory.
//
// The package is a standalone library and is not wired into the worker.
package bsrfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"

	"github.com/hashicorp/boundary/internal/storage"
)

// Store is the subset of *scratch.Store used by the adapter.
type Store interface {
	WriteFile(sessionID, name string, p []byte) (int, error)
	FilePath(sessionID, name string) (string, error)
}

// FS is a storage.FS for one session's scratch recording. The session must
// have been reserved in the store before use.
type FS struct {
	store Store
	id    string
}

var _ storage.FS = (*FS)(nil)

// New creates an FS for sessionID backed by store.
func New(store Store, sessionID string) (*FS, error) {
	if store == nil {
		return nil, errors.New("bsrfs: store is required")
	}
	if sessionID == "" {
		return nil, errors.New("bsrfs: session id is required")
	}
	return &FS{store: store, id: sessionID}, nil
}

// New creates the root container name. It fails with fs.ErrExist if it exists.
func (f *FS) New(_ context.Context, name string) (storage.Container, error) {
	p, err := f.store.FilePath(f.id, name)
	if err != nil {
		return nil, fmt.Errorf("bsrfs: %w", err)
	}
	if _, err := os.Lstat(p); err == nil {
		return nil, fs.ErrExist
	}
	if err := os.MkdirAll(p, 0o700); err != nil {
		return nil, fmt.Errorf("bsrfs: create container: %w", err)
	}
	return &container{fs: f, rel: name}, nil
}

// Open opens the existing root container name.
func (f *FS) Open(_ context.Context, name string) (storage.Container, error) {
	if err := f.requireDir(name); err != nil {
		return nil, err
	}
	return &container{fs: f, rel: name}, nil
}

func (f *FS) requireDir(rel string) error {
	p, err := f.store.FilePath(f.id, rel)
	if err != nil {
		return fmt.Errorf("bsrfs: %w", err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fs.ErrNotExist
	}
	return nil
}

type container struct {
	fs  *FS
	rel string
}

func (c *container) Close() error { return nil }

// child validates name on its own (path.Join would otherwise clean away ".."
// components) and returns its path relative to the recording's files.
func (c *container) child(name string) (string, error) {
	if _, err := c.fs.store.FilePath(c.fs.id, name); err != nil {
		return "", fmt.Errorf("bsrfs: %w", err)
	}
	return path.Join(c.rel, name), nil
}

func (c *container) Create(_ context.Context, name string) (storage.File, error) {
	return c.create(name)
}

func (c *container) create(name string) (storage.File, error) {
	rel, err := c.child(name)
	if err != nil {
		return nil, err
	}
	p, err := c.fs.store.FilePath(c.fs.id, rel)
	if err != nil {
		return nil, fmt.Errorf("bsrfs: %w", err)
	}
	if _, err := os.Lstat(p); err == nil {
		return nil, fs.ErrExist
	}
	// Creates the empty file; a zero-byte write needs no quota.
	if _, err := c.fs.store.WriteFile(c.fs.id, rel, nil); err != nil {
		return nil, err
	}
	return &file{fs: c.fs, rel: rel, path: p, writable: true}, nil
}

func (c *container) OpenFile(_ context.Context, name string, opt ...storage.Option) (storage.File, error) {
	o := storage.GetOpts(opt...)
	if o.WithCreateFile {
		return c.create(name)
	}
	rel, err := c.child(name)
	if err != nil {
		return nil, err
	}
	p, err := c.fs.store.FilePath(c.fs.id, rel)
	if err != nil {
		return nil, fmt.Errorf("bsrfs: %w", err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fs.ErrNotExist
	}
	f := &file{fs: c.fs, rel: rel, path: p, writable: o.WithFileAccessMode != storage.ReadOnly}
	if o.WithFileAccessMode != storage.WriteOnly {
		if f.r, err = os.Open(p); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (c *container) SubContainer(_ context.Context, name string, opt ...storage.Option) (storage.Container, error) {
	o := storage.GetOpts(opt...)
	rel, err := c.child(name)
	if err != nil {
		return nil, err
	}
	p, err := c.fs.store.FilePath(c.fs.id, rel)
	if err != nil {
		return nil, fmt.Errorf("bsrfs: %w", err)
	}
	if err := c.fs.requireDir(rel); err != nil {
		if !errors.Is(err, fs.ErrNotExist) || !o.WithCreateFile {
			return nil, err
		}
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, fmt.Errorf("bsrfs: create sub container: %w", err)
		}
	}
	return &container{fs: c.fs, rel: rel}, nil
}

type file struct {
	fs       *FS
	rel      string
	path     string
	writable bool
	r        *os.File
	closed   bool
}

func (f *file) Write(p []byte) (int, error) {
	if f.closed {
		return 0, errors.New("bsrfs: write on closed file")
	}
	if !f.writable {
		return 0, errors.New("bsrfs: read-only file")
	}
	return f.fs.store.WriteFile(f.fs.id, f.rel, p)
}

func (f *file) WriteString(s string) (int, error) { return f.Write([]byte(s)) }

func (f *file) WriteAndClose(p []byte) (int, error) {
	n, err := f.Write(p)
	if err != nil {
		_ = f.Close()
		return n, err
	}
	return n, f.Close()
}

func (f *file) Read(p []byte) (int, error) {
	if f.closed {
		return 0, errors.New("bsrfs: read on closed file")
	}
	if f.r == nil {
		return 0, errors.New("bsrfs: write-only file")
	}
	return f.r.Read(p)
}

func (f *file) Stat() (fs.FileInfo, error) { return os.Stat(f.path) }

func (f *file) Close() error {
	if f.closed {
		return errors.New("bsrfs: close on closed file")
	}
	f.closed = true
	if f.r != nil {
		return f.r.Close()
	}
	return nil
}
