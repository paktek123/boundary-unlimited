// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package event

import (
	"io"
	"sync"
)

// NetworkSinkFactory builds the writer that delivers formatted events for an
// http or syslog sink. The returned writer must never block and must never
// return errors that carry the destination or secrets.
type NetworkSinkFactory func(sc *SinkConfig) (io.Writer, error)

var (
	networkSinkMu      sync.RWMutex
	networkSinkFactory NetworkSinkFactory
)

// RegisterNetworkSinkFactory installs the factory that delivers events for
// http and syslog sinks (package netsink registers itself from init). Until a
// factory is registered those sink types are refused as not supported
// (enforcement-first). Passing nil unregisters it.
func RegisterNetworkSinkFactory(f NetworkSinkFactory) {
	networkSinkMu.Lock()
	defer networkSinkMu.Unlock()
	networkSinkFactory = f
}

func registeredNetworkSinkFactory() NetworkSinkFactory {
	networkSinkMu.RLock()
	defer networkSinkMu.RUnlock()
	return networkSinkFactory
}
