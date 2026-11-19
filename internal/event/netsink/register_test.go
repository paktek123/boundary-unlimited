// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package netsink

import (
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func eventerCfg() event.EventerConfig {
	return event.EventerConfig{
		SysEventsEnabled: true,
		Sinks: []*event.SinkConfig{{
			Name: "siem", EventTypes: []event.Type{event.SystemType}, Format: event.JSONSinkFormat,
			Type: event.HTTPSink,
			HTTPConfig: &event.HTTPSinkTypeConfig{
				URL: "https://siem.example.com/events", Token: "env://NETSINK_REGISTER_TEST_TOKEN",
				Format: event.HTTPFormatJSON,
			},
		}},
	}
}

// TestInitRegistersFactoryUsedByNewEventer builds a sink through the factory
// that this package registers in init, via event.NewEventer.
func TestInitRegistersFactoryUsedByNewEventer(t *testing.T) {
	lock := &sync.Mutex{}
	logger := hclog.New(&hclog.LoggerOptions{Mutex: lock})

	// Secret present: the real factory builds the sink and Validate accepts it.
	t.Setenv("NETSINK_REGISTER_TEST_TOKEN", canary)
	require.NoError(t, eventerCfg().Sinks[0].Validate())
	e, err := event.NewEventer(logger, lock, "netsink-register", eventerCfg())
	require.NoError(t, err)
	require.NotNil(t, e)

	// Secret missing: building fails closed with an error that does not echo the URL.
	t.Setenv("NETSINK_REGISTER_TEST_TOKEN", "")
	_, err = event.NewEventer(logger, lock, "netsink-register-nosecret", eventerCfg())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "siem.example.com")
}
