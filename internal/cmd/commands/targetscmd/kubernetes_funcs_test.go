// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package targetscmd

import (
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKubernetesActionsFlagsHaveNoRecordingFlags(t *testing.T) {
	for action, flags := range extraKubernetesActionsFlagsMapFuncImpl() {
		assert.NotContains(t, flags, "enable-session-recording", action)
		assert.NotContains(t, flags, "storage-bucket-id", action)
	}
}

func TestKubernetesFlagsHandling(t *testing.T) {
	c := &KubernetesCommand{}
	c.flagDefaultPort = "6443"
	c.flagDefaultClientPort = "null"
	c.flagSessionConnectionLimit = "-1"
	var opts []targets.Option
	require.True(t, extraKubernetesFlagsHandlingFuncImpl(c, nil, &opts))
	assert.Len(t, opts, 3)

	empty := &KubernetesCommand{}
	var none []targets.Option
	require.True(t, extraKubernetesFlagsHandlingFuncImpl(empty, nil, &none))
	assert.Empty(t, none)
}
