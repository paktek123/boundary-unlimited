// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"reflect"

	sshproxy "github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh"
)

// sshRecordingDeps are the pieces the ssh recording factory needs. Every field
// is optional here so that a worker lacking any of them stays fail closed:
// recording-required sessions are refused until all are present.
type sshRecordingDeps struct {
	Scratch   sshproxy.RecordingScratch
	Finalizer sshproxy.RecordingFinalizer
	Specs     sshproxy.SpecProvider
	Reporter  sshproxy.FinalizeReporter
}

// installSSHRecording installs the ssh recording factory only when every
// dependency is present. Otherwise it uninstalls any factory (so recorded
// sessions are refused with the handler's fixed error) and, when write is
// non-nil, emits one startup event naming the missing dependency classes. The
// event carries no ids, paths or secrets. It returns whether the factory was
// installed.
func installSSHRecording(ctx context.Context, d sshRecordingDeps, write sysEventWriter) (bool, error) {
	var missing []string
	if isNilIface(d.Scratch) {
		missing = append(missing, "recording_storage_path")
	}
	if isNilIface(d.Finalizer) {
		missing = append(missing, "finalizer")
	}
	if isNilIface(d.Specs) {
		missing = append(missing, "bsr_kms_wrapper")
	}
	if isNilIface(d.Reporter) {
		missing = append(missing, "reporter")
	}
	if len(missing) > 0 {
		sshproxy.InstallRecordingFactory(nil)
		if write != nil {
			write(ctx, "worker.installSSHRecording",
				"ssh session recording not available: sessions that require recording will be refused",
				"missing", missing)
		}
		return false, nil
	}
	f, err := sshproxy.NewRecordingFactory(sshproxy.RecordingFactoryDeps{
		Scratch: d.Scratch, Finalizer: d.Finalizer, Specs: d.Specs, Reporter: d.Reporter,
	})
	if err != nil {
		sshproxy.InstallRecordingFactory(nil)
		return false, err
	}
	sshproxy.InstallRecordingFactory(f)
	return true, nil
}

// isNilIface reports a nil interface or an interface holding a nil pointer.
func isNilIface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	}
	return false
}
