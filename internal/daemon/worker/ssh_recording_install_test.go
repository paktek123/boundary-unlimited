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

func TestInstallSSHRecording_UninstallsPreviousFactory(t *testing.T) {
	t.Cleanup(func() { sshproxy.InstallRecordingFactory(nil) })
	ok, err := installSSHRecording(context.Background(), sshRecordingDeps{}, nil)
	require.NoError(t, err)
	assert.False(t, ok)
}

type fakeFinalizer struct{}

func (fakeFinalizer) Finalize(context.Context, string) (upload.Result, error) {
	return upload.Result{}, nil
}

type fakeSpecs struct{}

func (fakeSpecs) RecordingSpec(context.Context, sshproxy.Authorization) (sshproxy.SessionRecordingSpec, error) {
	return sshproxy.SessionRecordingSpec{}, errors.New("not used")
}

type fakeReporter struct{}

func (fakeReporter) RecordingFinalized(context.Context, string, upload.Result, error) {}

func TestInstallSSHRecording_AllDepsInstallsFactory(t *testing.T) {
	t.Cleanup(func() { sshproxy.InstallRecordingFactory(nil) })
	store, err := scratch.New(t.TempDir(), 1<<20)
	require.NoError(t, err)

	ok, err := installSSHRecording(context.Background(), sshRecordingDeps{
		Scratch: store, Finalizer: fakeFinalizer{}, Specs: fakeSpecs{}, Reporter: fakeReporter{},
	}, nil)
	require.NoError(t, err)
	assert.True(t, ok)

	// Dropping any one dependency uninstalls the factory again (fail closed).
	for name, d := range map[string]sshRecordingDeps{
		"no finalizer": {Scratch: store, Specs: fakeSpecs{}, Reporter: fakeReporter{}},
		"no specs":     {Scratch: store, Finalizer: fakeFinalizer{}, Reporter: fakeReporter{}},
		"no reporter":  {Scratch: store, Finalizer: fakeFinalizer{}, Specs: fakeSpecs{}},
		"no scratch":   {Finalizer: fakeFinalizer{}, Specs: fakeSpecs{}, Reporter: fakeReporter{}},
	} {
		t.Run(name, func(t *testing.T) {
			ok, err := installSSHRecording(context.Background(), sshRecordingDeps{
				Scratch: store, Finalizer: fakeFinalizer{}, Specs: fakeSpecs{}, Reporter: fakeReporter{},
			}, nil)
			require.NoError(t, err)
			require.True(t, ok)
			ok, err = installSSHRecording(context.Background(), d, nil)
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}
