// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"errors"
	"testing"

	sshproxy "github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstallSSHRecording_MissingDepsFailClosed(t *testing.T) {
	var events []string
	var missing any
	write := func(_ context.Context, _ event.Op, msg string, args ...any) {
		events = append(events, msg)
		for i := 0; i+1 < len(args); i += 2 {
			if args[i] == "missing" {
				missing = args[i+1]
			}
		}
	}
	var nilStore *scratch.Store
	ok, err := installSSHRecording(context.Background(), sshRecordingDeps{Scratch: nilStore}, write)
	require.NoError(t, err)
	assert.False(t, ok)
	require.Len(t, events, 1)
	assert.ElementsMatch(t, []string{"recording_storage_path", "finalizer", "bsr_kms_wrapper", "reporter"}, missing)
}

func TestInstallSSHRecording_NilWriterOK(t *testing.T) {
	ok, err := installSSHRecording(context.Background(), sshRecordingDeps{}, nil)
	require.NoError(t, err)
	assert.False(t, ok)
}

type fakeFactory struct{}

func (fakeFactory) Wrap(context.Context, sshproxy.Authorization, sshproxy.Upstream) (sshproxy.Upstream, error) {
	return nil, errors.New("not used")
}

func TestInstallSSHRecording_UninstallsPreviousFactory(t *testing.T) {
	t.Cleanup(func() { sshproxy.InstallRecordingFactory(nil) })
	sshproxy.InstallRecordingFactory(fakeFactory{})
	require.True(t, sshproxy.RecordingFactoryInstalled())

	ok, err := installSSHRecording(context.Background(), sshRecordingDeps{}, nil)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.False(t, sshproxy.RecordingFactoryInstalled(), "missing deps must uninstall the factory")
}

type fakeFinalizer struct{}

func (fakeFinalizer) Finalize(context.Context, string) (upload.Result, error) {
	return upload.Result{}, nil
}

type unusedSpecs struct{}

func (unusedSpecs) RecordingSpec(context.Context, sshproxy.Authorization) (sshproxy.SessionRecordingSpec, error) {
	return sshproxy.SessionRecordingSpec{}, errors.New("not used")
}

type fakeReporter struct{}

func (fakeReporter) RecordingFinalized(context.Context, string, upload.Result, error) {}

func TestInstallSSHRecording_AllDepsInstallsFactory(t *testing.T) {
	t.Cleanup(func() { sshproxy.InstallRecordingFactory(nil) })
	store, err := scratch.New(t.TempDir(), 1<<20)
	require.NoError(t, err)

	ok, err := installSSHRecording(context.Background(), sshRecordingDeps{
		Scratch: store, Finalizer: fakeFinalizer{}, Specs: unusedSpecs{}, Reporter: fakeReporter{},
	}, nil)
	require.NoError(t, err)
	assert.True(t, ok)

	// Dropping any one dependency uninstalls the factory again (fail closed)
	// and the startup event names exactly that class.
	for name, tc := range map[string]struct {
		d       sshRecordingDeps
		missing string
	}{
		"no finalizer": {sshRecordingDeps{Scratch: store, Specs: unusedSpecs{}, Reporter: fakeReporter{}}, "finalizer"},
		"no specs":     {sshRecordingDeps{Scratch: store, Finalizer: fakeFinalizer{}, Reporter: fakeReporter{}}, "bsr_kms_wrapper"},
		"no reporter":  {sshRecordingDeps{Scratch: store, Finalizer: fakeFinalizer{}, Specs: unusedSpecs{}}, "reporter"},
		"no scratch":   {sshRecordingDeps{Finalizer: fakeFinalizer{}, Specs: unusedSpecs{}, Reporter: fakeReporter{}}, "recording_storage_path"},
	} {
		t.Run(name, func(t *testing.T) {
			ok, err := installSSHRecording(context.Background(), sshRecordingDeps{
				Scratch: store, Finalizer: fakeFinalizer{}, Specs: unusedSpecs{}, Reporter: fakeReporter{},
			}, nil)
			require.NoError(t, err)
			require.True(t, ok)
			require.True(t, sshproxy.RecordingFactoryInstalled())

			var missing any
			write := func(_ context.Context, _ event.Op, _ string, args ...any) {
				for i := 0; i+1 < len(args); i += 2 {
					if args[i] == "missing" {
						missing = args[i+1]
					}
				}
			}
			ok, err = installSSHRecording(context.Background(), tc.d, write)
			require.NoError(t, err)
			assert.False(t, ok)
			assert.False(t, sshproxy.RecordingFactoryInstalled())
			assert.Equal(t, []string{tc.missing}, missing)
		})
	}
}

func TestSSHRecordingDepsFor(t *testing.T) {
	// No scratch store: the dependency stays absent (no typed nil).
	d := sshRecordingDepsFor(nil, nil)
	assert.True(t, isNilIface(d.Scratch))
	// The reporter is always supplied (it only writes system events).
	assert.False(t, isNilIface(d.Reporter))

	// With a scratch store the scratch dependency is supplied too; the
	// factory stays uninstalled and the startup event does not name
	// recording_storage_path as missing.
	s, err := newSSHScratch(t.TempDir())
	require.NoError(t, err)
	d = sshRecordingDepsFor(s, nil)
	assert.False(t, isNilIface(d.Scratch))
	var missing any
	write := func(_ context.Context, _ event.Op, _ string, args ...any) {
		for i := 0; i+1 < len(args); i += 2 {
			if args[i] == "missing" {
				missing = args[i+1]
			}
		}
	}
	ok, err := installSSHRecording(context.Background(), d, write)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.ElementsMatch(t, []string{"finalizer", "bsr_kms_wrapper"}, missing)
}
