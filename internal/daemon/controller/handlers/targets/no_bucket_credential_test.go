// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package targets_test

import (
	"strings"
	"testing"

	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// TestClientSessionAuthorizationHasNoBucketCredential guards the binding
// security decision on #348/#365: the recording bucket credential is only ever
// returned to the requesting worker through LookupSession, never to the client.
// It walks the client-facing SessionAuthorization message (the type returned by
// AuthorizeSession) and fails if any field is named like a bucket, storage or
// secret reference.
func TestClientSessionAuthorizationHasNoBucketCredential(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		for i := 0; i < md.Fields().Len(); i++ {
			f := md.Fields().Get(i)
			name := strings.ToLower(string(f.Name()))
			for _, bad := range []string{"bucket", "storage"} {
				assert.NotContains(t, name, bad, "field %s.%s must not reach the client", md.FullName(), f.Name())
			}
			if f.Message() != nil {
				walk(f.Message())
			}
		}
	}
	walk((&pb.SessionAuthorization{}).ProtoReflect().Descriptor())
}
