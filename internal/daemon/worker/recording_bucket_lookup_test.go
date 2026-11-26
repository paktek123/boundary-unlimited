// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLookupSessionBucketLookup(t *testing.T) {
	const canary = "canary-bucket-secret"
	ok := &services.LookupSessionResponse{RecordingBucket: &services.RecordingBucket{StorageBucketId: "sb_1234567890", Secret: []byte(canary)}}
	for name, tc := range map[string]struct {
		fetch SessionLookupFunc
		id    string
		want  bool
	}{
		"nil fetch":     {nil, "s_1", false},
		"empty session": {func(context.Context, string) (*services.LookupSessionResponse, error) { return ok, nil }, "", false},
		"fetch error":   {func(context.Context, string) (*services.LookupSessionResponse, error) { return ok, errors.New(canary) }, "s_1", false},
		"nil response":  {func(context.Context, string) (*services.LookupSessionResponse, error) { return nil, nil }, "s_1", false},
		"no bucket": {func(context.Context, string) (*services.LookupSessionResponse, error) {
			return &services.LookupSessionResponse{}, nil
		}, "s_1", false},
		"empty bucket id": {func(context.Context, string) (*services.LookupSessionResponse, error) {
			return &services.LookupSessionResponse{RecordingBucket: &services.RecordingBucket{Secret: []byte(canary)}}, nil
		}, "s_1", false},
		"empty secret": {func(context.Context, string) (*services.LookupSessionResponse, error) {
			return &services.LookupSessionResponse{RecordingBucket: &services.RecordingBucket{StorageBucketId: "sb_1234567890"}}, nil
		}, "s_1", false},
		"present": {func(context.Context, string) (*services.LookupSessionResponse, error) { return ok, nil }, "s_1", true},
	} {
		t.Run(name, func(t *testing.T) {
			ref, err := NewLookupSessionBucketLookup(tc.fetch)(context.Background(), tc.id)
			if !tc.want {
				require.ErrorIs(t, err, ErrNoRecordingBucket)
				assert.NotContains(t, err.Error(), canary)
				assert.Empty(t, ref.Secret)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "sb_1234567890", ref.BucketId)
			assert.Equal(t, canary, string(ref.Secret))
			// The ref is a copy: mutating it must not touch the response.
			ref.Secret[0] = 'X'
			assert.Equal(t, canary, string(ok.RecordingBucket.Secret))
			// Redaction in every formatting path.
			js, err := json.Marshal(ref)
			require.NoError(t, err)
			for _, s := range []string{fmt.Sprintf("%v", ref), fmt.Sprintf("%+v", ref), fmt.Sprintf("%#v", ref), string(js)} {
				assert.NotContains(t, s, canary)
			}
		})
	}
}

// With the lookup wired into the bucket source, an absent bucket (controller
// not populating it yet) refuses the session.
func TestLookupSessionBucketLookup_SourceFailsClosed(t *testing.T) {
	look := NewLookupSessionBucketLookup(func(context.Context, string) (*services.LookupSessionResponse, error) {
		return &services.LookupSessionResponse{}, nil
	})
	opened := false
	src := NewSessionBucketSource(look, func(context.Context, SessionBucketRef) (RecordingBucketSession, error) {
		opened = true
		return nil, errors.New("must not open")
	})
	_, err := src.Open(context.Background(), "s_1")
	require.ErrorIs(t, err, ErrRecordingBucketUnavailable)
	assert.False(t, opened)
}
