// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package event

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func netSinkEventerConfig() EventerConfig {
	return EventerConfig{
		SysEventsEnabled: true,
		Sinks: []*SinkConfig{{
			Name: "siem", EventTypes: []Type{SystemType}, Format: JSONSinkFormat,
			Type: HTTPSink, HTTPConfig: validHTTP(),
		}},
	}
}

func TestNetworkSinkFactory_NotRegisteredFailsClosed(t *testing.T) {
	RegisterNetworkSinkFactory(nil)
	lock := &sync.Mutex{}
	_, err := NewEventer(hclog.New(&hclog.LoggerOptions{Mutex: lock}), lock, "net-none", netSinkEventerConfig())
	require.ErrorIs(t, err, ErrNetworkSinkNotSupported)
}

func TestNetworkSinkFactory_RegisteredDeliversEvents(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	RegisterNetworkSinkFactory(func(*SinkConfig) (io.Writer, error) {
		return writerFunc(func(p []byte) (int, error) {
			mu.Lock()
			defer mu.Unlock()
			return buf.Write(p)
		}), nil
	})
	t.Cleanup(func() { RegisterNetworkSinkFactory(nil) })

	sc := netSinkEventerConfig().Sinks[0]
	require.NoError(t, sc.Validate())

	lock := &sync.Mutex{}
	e, err := NewEventer(hclog.New(&hclog.LoggerOptions{Mutex: lock}), lock, "net-ok", netSinkEventerConfig())
	require.NoError(t, err)
	require.NoError(t, e.writeSysEvent(context.Background(), &sysEvent{Op: "test.op", Data: map[string]any{"msg": "hello network sink"}}))
	require.NoError(t, e.FlushNodes(context.Background()))
	mu.Lock()
	defer mu.Unlock()
	assert.Contains(t, buf.String(), "hello network sink")
}

func TestNetworkSinkFactory_BuildErrorFailsClosed(t *testing.T) {
	RegisterNetworkSinkFactory(func(*SinkConfig) (io.Writer, error) { return nil, errors.New("boom") })
	t.Cleanup(func() { RegisterNetworkSinkFactory(nil) })
	lock := &sync.Mutex{}
	_, err := NewEventer(hclog.New(&hclog.LoggerOptions{Mutex: lock}), lock, "net-err", netSinkEventerConfig())
	require.Error(t, err)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
