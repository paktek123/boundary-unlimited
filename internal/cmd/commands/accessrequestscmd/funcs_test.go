// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequestscmd

import (
	"math"
	"testing"

	"github.com/hashicorp/boundary/api/accessrequests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDurationSeconds(t *testing.T) {
	tests := []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"3600", 3600, true},
		{"1h", 3600, true},
		{"90s", 90, true},
		{"0", 0, false},
		{"500ms", 0, false},
		{"-5s", 0, false},
		{"nonsense", 0, false},
		{"4294967296", 0, false},
		{"2000000000h", 0, false},
		{"4294967295", math.MaxUint32, true},
	}
	for _, tt := range tests {
		got, ok := parseDurationSeconds(tt.in)
		assert.Equal(t, tt.ok, ok, tt.in)
		if tt.ok {
			assert.Equal(t, tt.want, got, tt.in)
		}
	}
}

func TestExtraFlagsHandling(t *testing.T) {
	c := &Command{}
	c.flagJustification = "incident"
	c.flagGrants = []string{"ids=*;type=target;actions=read", "ids=*;type=target;actions=authorize-session"}
	c.flagDuration = "1h"
	var opts []accessrequests.Option
	require.True(t, extraFlagsHandlingFuncImpl(c, nil, &opts))
	assert.Len(t, opts, 3)

	empty := &Command{}
	var none []accessrequests.Option
	require.True(t, extraFlagsHandlingFuncImpl(empty, nil, &none))
	assert.Empty(t, none)
}
