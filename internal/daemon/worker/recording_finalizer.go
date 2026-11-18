// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/finalize"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
	"github.com/hashicorp/boundary/internal/storage"
)

// Errors of the recording finalizer. They are fixed classes: they never carry
// credentials, bucket names, file names or paths.
var (
	ErrRecordingUpload     = errors.New("worker: recording upload failed")
	ErrRecordingValidation = errors.New("worker: recording failed validation")
)

// RecordingBucketSession is an open connection to the session's storage
// bucket. The credentials behind it are supplied by the controller for this
// session, are held in memory only and are dropped by Close.
type RecordingBucketSession interface {
	// Put writes one file at the slash-separated relative path rel.
	Put(ctx context.Context, rel string, r io.Reader) error
	Close() error
}

// RecordingBucketSource opens the bucket for a session. It must never write
// the credentials to scratch, config files, events or logs.
type RecordingBucketSource interface {
	Open(ctx context.Context, sessionId string) (RecordingBucketSession, error)
}

// storageUploader implements upload.Uploader: it copies the finished
// recording directory to the storage bucket and returns nil only after every
// file was stored. It never touches the scratch data.
type storageUploader struct{ src RecordingBucketSource }

var _ upload.Uploader = storageUploader{}

func (u storageUploader) Upload(ctx context.Context, rec upload.Recording) (err error) {
	bs, err := u.src.Open(ctx, rec.SessionID)
	if err != nil || bs == nil {
		return fmt.Errorf("%w: bucket unavailable", ErrRecordingUpload)
	}
	defer func() {
		if cerr := bs.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("%w: close", ErrRecordingUpload)
		}
	}()
	walkErr := filepath.WalkDir(rec.Dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return errors.New("symlink")
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return errors.New("irregular file")
		}
		rel, rerr := filepath.Rel(rec.Dir, p)
		if rerr != nil {
			return rerr
		}
		f, oerr := os.Open(p)
		if oerr != nil {
			return oerr
		}
		defer f.Close()
		return bs.Put(ctx, filepath.ToSlash(rel), f)
	})
	if walkErr != nil {
		return fmt.Errorf("%w: store", ErrRecordingUpload)
	}
	return nil
}

// bsrValidator implements upload.Validator over bsr.Validate: a recording
// that is invalid, or cannot be validated, is never uploaded.
type bsrValidator struct {
	openFS func(rec upload.Recording) (storage.FS, error)
	unwrap kms.KeyUnwrapCallbackFunc
}

var _ upload.Validator = bsrValidator{}

func (v bsrValidator) Validate(ctx context.Context, rec upload.Recording) error {
	f, err := v.openFS(rec)
	if err != nil || f == nil {
		return fmt.Errorf("%w: cannot open recording", ErrRecordingValidation)
	}
	res, err := bsr.Validate(ctx, rec.SessionID, f, v.unwrap)
	if err != nil || res == nil || !res.Valid {
		return fmt.Errorf("%w", ErrRecordingValidation)
	}
	return nil
}

// recordingFinalizerDeps are the dependencies of newRecordingFinalizer. All
// are required.
type recordingFinalizerDeps struct {
	Scratch   finalize.Scratch
	Buckets   RecordingBucketSource
	Validator upload.Validator
	Clock     upload.Clock
	Events    upload.EventSink
	Options   upload.Options
}

// newRecordingFinalizer returns a finalizer that validates a finished
// recording before upload, uploads it to the storage bucket and removes the
// scratch data only after a successful upload. It satisfies the ssh package's
// RecordingFinalizer. It is not installed anywhere yet and adds no config.
func newRecordingFinalizer(d recordingFinalizerDeps) (*finalize.Finalizer, error) {
	if d.Buckets == nil {
		return nil, fmt.Errorf("%w: missing bucket source", ErrRecordingUpload)
	}
	mgr, err := upload.New(storageUploader{src: d.Buckets}, d.Validator, d.Clock, d.Events, d.Options)
	if err != nil {
		return nil, fmt.Errorf("%w: upload manager", ErrRecordingUpload)
	}
	f, err := finalize.New(d.Scratch, mgr)
	if err != nil {
		return nil, fmt.Errorf("%w: finalizer", ErrRecordingUpload)
	}
	return f, nil
}
