// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package controller

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/notify/sender"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildNotifier(t *testing.T) {
	ctx := context.Background()
	const canary = "canary-secret-value-0123456789"
	okResolver := func(string) ([]byte, error) { return []byte(canary), nil }
	valid := sender.Destination{Name: "ops", Type: sender.TypeWebhook, URL: "https://hooks.example.com/x", SecretRef: "env://NOTIFY_SECRET"}

	t.Run("no destinations means no notifier", func(t *testing.T) {
		n, err := buildNotifier(ctx, nil, sender.Deps{}, 0, okResolver)
		require.NoError(t, err)
		assert.Nil(t, n)
	})
	t.Run("valid destination builds", func(t *testing.T) {
		n, err := buildNotifier(ctx, []sender.Destination{valid}, sender.Deps{}, 0, okResolver)
		require.NoError(t, err)
		assert.NotNil(t, n)
	})
	for name, tc := range map[string]struct {
		dests   []sender.Destination
		resolve sender.SecretResolver
	}{
		"http url":      {[]sender.Destination{{Name: "ops", Type: sender.TypeWebhook, URL: "http://hooks.example.com/x", SecretRef: "env://S"}}, okResolver},
		"unknown type":  {[]sender.Destination{{Name: "ops", Type: "pager", URL: valid.URL, SecretRef: "env://S"}}, okResolver},
		"inline secret": {[]sender.Destination{{Name: "ops", Type: sender.TypeWebhook, URL: valid.URL, SecretRef: canary}}, okResolver},
		"unresolvable":  {[]sender.Destination{valid}, func(string) ([]byte, error) { return nil, sender.ErrSecretUnavailable }},
		"short secret":  {[]sender.Destination{valid}, func(string) ([]byte, error) { return []byte("x"), nil }},
		"duplicate":     {[]sender.Destination{valid, valid}, okResolver},
	} {
		t.Run(name, func(t *testing.T) {
			n, err := buildNotifier(ctx, tc.dests, sender.Deps{}, 0, tc.resolve)
			require.Error(t, err)
			assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			assert.Contains(t, err.Error(), errNotifierBuildMsg)
			assert.Nil(t, n)
			assert.NotContains(t, err.Error(), canary)
			assert.NotContains(t, err.Error(), "hooks.example.com")
		})
	}
}
