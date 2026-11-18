// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package kms

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeysFormattingIsRedacted(t *testing.T) {
	k, err := CreateKeys(context.Background(), TestWrapper(t), "s_1234567890")
	require.NoError(t, err)
	for _, out := range []string{
		fmt.Sprintf("%v", k), fmt.Sprintf("%+v", k), k.String(), fmt.Sprintf("%#v", k),
	} {
		assert.Equal(t, redacted, out)
		assert.NotContains(t, out, string(k.BsrKey.Key))
	}
}
