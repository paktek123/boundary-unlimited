// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"

	"github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

// SessionLookupFunc fetches the controller's LookupSession response for a
// session on behalf of this worker.
type SessionLookupFunc func(ctx context.Context, sessionId string) (*services.LookupSessionResponse, error)

// NewLookupSessionBucketLookup builds a SessionBucketLookup that reads the
// recording bucket from the LookupSession response. It copies the secret out of
// the response into the redacting SessionBucketRef and holds nothing across
// calls (no cache). A nil fetch func, a lookup error, a missing recording
// bucket, an empty bucket id or an empty secret all yield
// ErrNoRecordingBucket, so callers fail closed and the cause (which could
// echo response data) is dropped.
func NewLookupSessionBucketLookup(fetch SessionLookupFunc) SessionBucketLookup {
	return func(ctx context.Context, sessionId string) (SessionBucketRef, error) {
		if fetch == nil || sessionId == "" {
			return SessionBucketRef{}, ErrNoRecordingBucket
		}
		resp, err := fetch(ctx, sessionId)
		if err != nil || resp == nil {
			return SessionBucketRef{}, ErrNoRecordingBucket
		}
		rb := resp.GetRecordingBucket()
		if rb.GetStorageBucketId() == "" || len(rb.GetSecret()) == 0 {
			return SessionBucketRef{}, ErrNoRecordingBucket
		}
		secret := make([]byte, len(rb.GetSecret()))
		copy(secret, rb.GetSecret())
		return SessionBucketRef{BucketId: rb.GetStorageBucketId(), Secret: secret}, nil
	}
}
