// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package kubernetes

import (
	"context"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/kubernetes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func attr(port, clientPort *uint32) *attribute {
	a := &pb.KubernetesTargetAttributes{}
	if port != nil {
		a.DefaultPort = &wrappers.UInt32Value{Value: *port}
	}
	if clientPort != nil {
		a.DefaultClientPort = &wrappers.UInt32Value{Value: *clientPort}
	}
	return &attribute{a}
}

func u(v uint32) *uint32 { return &v }

func TestVet(t *testing.T) {
	assert.Empty(t, attr(nil, nil).Vet())
	assert.Empty(t, attr(u(6443), u(8080)).Vet())
	assert.Contains(t, attr(u(0), nil).Vet(), defaultPortField)
	assert.Empty(t, attr(u(65535), u(65535)).Vet())
	assert.Contains(t, attr(u(65536), nil).Vet(), defaultPortField)
	assert.Contains(t, attr(nil, u(0)).Vet(), defaultClientPortField)
	assert.Contains(t, attr(nil, u(70000)).Vet(), defaultClientPortField)
}

func TestVetForUpdate(t *testing.T) {
	assert.Contains(t, attr(nil, nil).VetForUpdate([]string{defaultPortField}), defaultPortField)
	assert.Contains(t, attr(u(0), nil).VetForUpdate([]string{defaultPortField}), defaultPortField)
	assert.Empty(t, attr(u(6443), nil).VetForUpdate([]string{defaultPortField}))
	// fields not in the mask are not vetted
	assert.Empty(t, attr(u(0), nil).VetForUpdate([]string{defaultClientPortField}))
}

func TestOptionsDefaultPort(t *testing.T) {
	opts := attr(nil, nil).Options()
	require.Len(t, opts, 1)
	o := target.GetOpts(opts...)
	assert.Equal(t, uint32(443), o.WithDefaultPort)
	o = target.GetOpts(attr(u(6443), u(8080)).Options()...)
	assert.Equal(t, uint32(6443), o.WithDefaultPort)
	assert.Equal(t, uint32(8080), o.WithDefaultClientPort)
}

func TestSetAttributes(t *testing.T) {
	out := &pb.Target{}
	require.NoError(t, setAttributes(nil, out))
	assert.Nil(t, out.Attrs)
	require.NotNil(t, newAttribute(&pb.Target_KubernetesTargetAttributes{KubernetesTargetAttributes: &pb.KubernetesTargetAttributes{}}))

	tgt, err := target.New(context.Background(), kubernetes.Subtype, "p_1234567890",
		target.WithName("k"), target.WithAddress("k8s.example.com"),
		target.WithDefaultPort(6443), target.WithDefaultClientPort(8080))
	require.NoError(t, err)
	out = &pb.Target{}
	require.NoError(t, setAttributes(tgt, out))
	got := out.GetKubernetesTargetAttributes()
	require.NotNil(t, got)
	assert.Equal(t, uint32(6443), got.GetDefaultPort().GetValue())
	assert.Equal(t, uint32(8080), got.GetDefaultClientPort().GetValue())

	tgt, err = target.New(context.Background(), kubernetes.Subtype, "p_1234567890",
		target.WithName("k"), target.WithAddress("k8s.example.com"), target.WithDefaultPort(6443))
	require.NoError(t, err)
	out = &pb.Target{}
	require.NoError(t, setAttributes(tgt, out))
	assert.Nil(t, out.GetKubernetesTargetAttributes().GetDefaultClientPort())
}
