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

type closableWriter struct {
	writerFunc
	closed int
}

func (c *closableWriter) Close(context.Context) error { c.closed++; return nil }

func TestNetworkSinkFactory_FlushNodesClosesSinks(t *testing.T) {
	cw := &closableWriter{writerFunc: func(p []byte) (int, error) { return len(p), nil }}
	RegisterNetworkSinkFactory(func(*SinkConfig) (io.Writer, error) { return cw, nil })
	t.Cleanup(func() { RegisterNetworkSinkFactory(nil) })
	lock := &sync.Mutex{}
	e, err := NewEventer(hclog.New(&hclog.LoggerOptions{Mutex: lock}), lock, "net-close", netSinkEventerConfig())
	require.NoError(t, err)
	require.NoError(t, e.FlushNodes(context.Background()))
	assert.Equal(t, 1, cw.closed)
}

type errClosableWriter struct {
	writerFunc
	err    error
	closed int
}

func (c *errClosableWriter) Close(context.Context) error { c.closed++; return c.err }

func TestNetworkSinkFactory_FlushNodesCloseErrorsAndRepeat(t *testing.T) {
	boom := errors.New("dropped entries")
	cw := &errClosableWriter{writerFunc: func(p []byte) (int, error) { return len(p), nil }, err: boom}
	RegisterNetworkSinkFactory(func(*SinkConfig) (io.Writer, error) { return cw, nil })
	t.Cleanup(func() { RegisterNetworkSinkFactory(nil) })
	lock := &sync.Mutex{}
	e, err := NewEventer(hclog.New(&hclog.LoggerOptions{Mutex: lock}), lock, "net-close-err", netSinkEventerConfig())
	require.NoError(t, err)

	// A close error is returned wrapped, and does not hide the cause.
	err = e.FlushNodes(context.Background())
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "closing network sinks")

	// A second flush calls Close again; sinks must tolerate that (the real
	// netsink.Sink does: sinkqueue.Batcher.Close is idempotent).
	_ = e.FlushNodes(context.Background())
	assert.Equal(t, 2, cw.closed)
}

func TestNetworkSinkFactory_FlushNodesPassesContext(t *testing.T) {
	var got context.Context
	cw := &ctxClosableWriter{fn: func(ctx context.Context) error { got = ctx; return ctx.Err() }}
	RegisterNetworkSinkFactory(func(*SinkConfig) (io.Writer, error) { return cw, nil })
	t.Cleanup(func() { RegisterNetworkSinkFactory(nil) })
	lock := &sync.Mutex{}
	e, err := NewEventer(hclog.New(&hclog.LoggerOptions{Mutex: lock}), lock, "net-close-ctx", netSinkEventerConfig())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = e.FlushNodes(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, ctx, got, "the caller's context bounds the drain")
}

type ctxClosableWriter struct{ fn func(context.Context) error }

func (c *ctxClosableWriter) Write(p []byte) (int, error)     { return len(p), nil }
func (c *ctxClosableWriter) Close(ctx context.Context) error { return c.fn(ctx) }
