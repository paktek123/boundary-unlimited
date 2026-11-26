// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package targetscmd

import (
	"testing"

	"github.com/mitchellh/cli"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
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

func TestKubernetesFlagsHandlingTable(t *testing.T) {
	cases := []struct {
		name    string
		set     func(c *KubernetesCommand)
		wantOk  bool
		wantLen int
	}{
		{"port not a number", func(c *KubernetesCommand) { c.flagDefaultPort = "abc" }, false, 0},
		{"port overflow", func(c *KubernetesCommand) { c.flagDefaultPort = "99999999999" }, false, 0},
		{"client port invalid", func(c *KubernetesCommand) { c.flagDefaultClientPort = "x" }, false, 0},
		{"session max integer", func(c *KubernetesCommand) { c.flagSessionMaxSeconds = "3600" }, true, 1},
		{"session max duration", func(c *KubernetesCommand) { c.flagSessionMaxSeconds = "1h" }, true, 1},
		{"session max null", func(c *KubernetesCommand) { c.flagSessionMaxSeconds = "null" }, true, 1},
		{"session max invalid", func(c *KubernetesCommand) { c.flagSessionMaxSeconds = "soon" }, false, 0},
		{"session max negative duration", func(c *KubernetesCommand) { c.flagSessionMaxSeconds = "-1h" }, false, 0},
		{"session max huge duration", func(c *KubernetesCommand) { c.flagSessionMaxSeconds = "2000000h" }, false, 0},
		{"connection limit invalid", func(c *KubernetesCommand) { c.flagSessionConnectionLimit = "many" }, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &KubernetesCommand{Command: base.NewCommand(cli.NewMockUi())}
			tc.set(c)
			var opts []targets.Option
			assert.Equal(t, tc.wantOk, extraKubernetesFlagsHandlingFuncImpl(c, nil, &opts))
			if tc.wantOk {
				assert.Len(t, opts, tc.wantLen)
			}
		})
	}
}
