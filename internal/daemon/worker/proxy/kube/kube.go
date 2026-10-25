// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package kube relays an already-authorized client connection to a Kubernetes
// API server over mandatory, verified TLS. It takes all of its inputs as plain
// values, is not registered as a worker proxy handler and enables nothing by
// itself.
package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
)

const dialTimeout = 10 * time.Second

// Config describes the API server to connect to. Credential material is held
// in memory only and is never logged or included in errors.
type Config struct {
	// Address is the host:port of the API server.
	Address string
	// CAPEM is the PEM encoded CA bundle used to verify the API server. It is
	// required: system roots are never used.
	CAPEM []byte
	// ServerName is the name the API server certificate must be valid for.
	ServerName string
	// ClientCertPEM and ClientKeyPEM optionally provide a client certificate
	// for mutual TLS. Both or neither must be set.
	ClientCertPEM []byte
	ClientKeyPEM  []byte
}

// Proxy relays connections to a single API server.
type Proxy struct {
	address   string
	tlsConfig *tls.Config
	dialer    func(ctx context.Context, network, addr string) (net.Conn, error)

	active   atomic.Int64
	bytesIn  atomic.Int64 // bytes from the API server to the client
	bytesOut atomic.Int64 // bytes from the client to the API server
}

// New validates cfg and returns a Proxy. No connection is made.
func New(ctx context.Context, cfg Config) (*Proxy, error) {
	const op = "kube.New"
	switch {
	case cfg.Address == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "address is empty")
	case cfg.ServerName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "server name is empty")
	case len(cfg.CAPEM) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "ca bundle is empty")
	case (len(cfg.ClientCertPEM) == 0) != (len(cfg.ClientKeyPEM) == 0):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "client certificate and key must be set together")
	}
	if _, _, err := net.SplitHostPort(cfg.Address); err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "address must be host:port")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.CAPEM) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "ca bundle contains no valid certificates")
	}
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: cfg.ServerName,
		MinVersion: tls.VersionTLS12,
	}
	if len(cfg.ClientCertPEM) > 0 {
		cert, err := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
		if err != nil {
			// The underlying error is not wrapped: it may echo key material.
			return nil, errors.New(ctx, errors.InvalidParameter, op, "client certificate and key are invalid")
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	d := &net.Dialer{Timeout: dialTimeout}
	return &Proxy{address: cfg.Address, tlsConfig: tlsCfg, dialer: d.DialContext}, nil
}

// ActiveConnections returns the number of connections currently being relayed.
func (p *Proxy) ActiveConnections() int64 { return p.active.Load() }

// BytesRelayed returns the total bytes relayed from the API server to the
// client and from the client to the API server.
func (p *Proxy) BytesRelayed() (fromServer, fromClient int64) {
	return p.bytesIn.Load(), p.bytesOut.Load()
}

// Relay dials the API server, verifies it, and copies bytes in both directions
// until either side closes or ctx is cancelled. It always closes client. The
// connection is refused, with nothing relayed, if TLS verification fails.
func (p *Proxy) Relay(ctx context.Context, client net.Conn) error {
	const op = "kube.(Proxy).Relay"
	if client == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "client conn is nil")
	}
	defer client.Close()

	raw, err := p.dialer(ctx, "tcp", p.address)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("dialing api server"))
	}
	server := tls.Client(raw, p.tlsConfig)
	hsCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if err := server.HandshakeContext(hsCtx); err != nil {
		_ = raw.Close()
		return errors.Wrap(ctx, err, op, errors.WithMsg("api server tls handshake failed"))
	}

	p.active.Add(1)
	defer p.active.Add(-1)

	stop := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = server.Close()
	})
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, server)
		p.bytesIn.Add(n)
		_ = client.Close()
		_ = server.Close()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(server, client)
		p.bytesOut.Add(n)
		_ = server.Close()
		_ = client.Close()
	}()
	wg.Wait()
	return nil
}
