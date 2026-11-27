// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"testing"

	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestRecordingAttributesRefused guards the enforcement-first rule of #11: the
// API must not accept enable_session_recording or storage_bucket_id on an ssh
// target until the worker enforces recording end to end.
func TestRecordingAttributesRefused(t *testing.T) {
	enable := &pb.SshTargetAttributes{EnableSessionRecording: wrapperspb.Bool(true)}
	bucket := &pb.SshTargetAttributes{StorageBucketId: wrapperspb.String("sb_1234567890")}
	off := &pb.SshTargetAttributes{EnableSessionRecording: wrapperspb.Bool(false), StorageBucketId: wrapperspb.String("")}

	t.Run("create", func(t *testing.T) {
		assert.Contains(t, (&attribute{enable}).Vet(), enableRecordingField)
		assert.Contains(t, (&attribute{bucket}).Vet(), storageBucketIdField)
		assert.Empty(t, (&attribute{off}).Vet())
		assert.Empty(t, (&attribute{&pb.SshTargetAttributes{}}).Vet())
	})
	t.Run("update", func(t *testing.T) {
		assert.Contains(t, (&attribute{enable}).VetForUpdate([]string{enableRecordingField}), enableRecordingField)
		assert.Contains(t, (&attribute{bucket}).VetForUpdate([]string{storageBucketIdField}), storageBucketIdField)
		assert.Empty(t, (&attribute{off}).VetForUpdate([]string{enableRecordingField, storageBucketIdField}))
		// a mask that does not name the recording fields does not touch them
		assert.Empty(t, (&attribute{&pb.SshTargetAttributes{}}).VetForUpdate([]string{"name"}))
	})
}
