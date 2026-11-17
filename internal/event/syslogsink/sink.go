// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package syslogsink is the network transport for RFC 5424 syslog event
// sinks: UDP datagrams, TCP and TLS with octet-counted framing. It implements
// sinkqueue.Sender over entries framed by internal/event/syslogfmt. Nothing in
// the event system selects it yet: there is no sink type or HCL option, so no
// configuration can turn it on.
package syslogsink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/hashicorp/boundary/internal/event/syslogfmt"
	"github.com/hashicorp/boundary/internal/netguard"
)

// Network is the transport.
type Network string

// Transports.
const (
	UDP Network = "udp"
	TCP Network = "tcp"
	TLS Network = "tls"
)

// Defaults.
const (
	DefaultDialTimeout  = 5 * time.Second
	DefaultWriteTimeout = 5 * time.Second
)

// Errors. They never carry entry contents.
var (
	ErrInvalidConfig = errors.New("syslogsink: invalid configuration")
	ErrDelivery      = errors.New("syslogsink: delivery failed")
)

// Config configures a Sender.
type Config struct {
	Network Network
	// Address is host:port of the collector.
	Address string
	// RootCAs verifies the collector for TLS; nil uses the system roots.
	RootCAs *x509.CertPool
	// ServerName overrides the name verified in the collector certificate;
	// empty uses the host of Address.
	ServerName string
	// ClientCert is an optional client certificate for mutual TLS.
	ClientCert *tls.Certificate
	// DialTimeout and WriteTimeout default when zero; negative is invalid.
	DialTimeout  time.Duration
	WriteTimeout time.Duration
	// Resolver resolves the collector host; nil uses the system resolver.
	Resolver netguard.Resolver
	// AllowedCIDRs is the explicit opt-in allowlist for the egress guard.
	// Loopback, private, link-local and metadata destinations are refused
	// unless they fall inside it (checked on the resolved address at connect
	// time). Wildcard prefixes are invalid.
	AllowedCIDRs []netip.Prefix
}

// Sender delivers batches of already-framed entries.
type Sender struct {
	cfg Config
}

// New validates cfg. There is deliberately no option to skip certificate
// verification and the minimum TLS version is fixed at 1.2.
func New(cfg Config) (*Sender, error) {
	switch cfg.Network {
	case UDP, TCP, TLS:
	default:
		return nil, fmt.Errorf("%w: unknown network", ErrInvalidConfig)
	}
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("%w: address must be host:port", ErrInvalidConfig)
	}
	if cfg.DialTimeout < 0 || cfg.WriteTimeout < 0 {
		return nil, fmt.Errorf("%w: negative timeout", ErrInvalidConfig)
	}
	if cfg.Network != TLS && (cfg.RootCAs != nil || cfg.ServerName != "" || cfg.ClientCert != nil) {
		return nil, fmt.Errorf("%w: TLS options require the tls network", ErrInvalidConfig)
	}
	for _, p := range cfg.AllowedCIDRs {
		if !p.IsValid() || p.Bits() == 0 {
			return nil, fmt.Errorf("%w: allowed cidr", ErrInvalidConfig)
		}
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = DefaultWriteTimeout
	}
	return &Sender{cfg: cfg}, nil
}

// Frame formats msg for the sender's transport: a datagram for UDP and an
// octet-counted frame for TCP and TLS.
func (s *Sender) Frame(msg syslogfmt.Message) ([]byte, error) {
	if s.cfg.Network == UDP {
		return syslogfmt.FormatDatagram(msg)
	}
	return syslogfmt.FormatOctetCounted(msg)
}

// Send implements sinkqueue.Sender. Entries must already be framed for the
// transport with Frame (so UDP entries respect syslogfmt.MaxDatagramSize);
// Send writes them as given. A persistent connection instead of dialling per
// batch is a possible follow-up if throughput matters. It dials, writes every entry in order and
// closes the connection. Any failure returns ErrDelivery so the caller can
// retry the whole batch; for TCP and TLS this can duplicate entries that were
// already written (at-least-once).
func (s *Sender) Send(ctx context.Context, batch [][]byte) (err error) {
	if len(batch) == 0 {
		return nil
	}
	dctx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
	defer cancel()
	conn, err := s.dial(dctx)
	if err != nil {
		return ErrDelivery
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil && err == nil {
			err = ErrDelivery
		}
	}()
	for _, e := range batch {
		if err := ctx.Err(); err != nil {
			return ErrDelivery
		}
		_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
		if _, werr := conn.Write(e); werr != nil {
			return ErrDelivery
		}
	}
	return nil
}

// dial connects only through the netguard egress guard: the destination is
// resolved here and every address must be allowed before and at connect time.
func (s *Sender) dial(ctx context.Context) (net.Conn, error) {
	if s.cfg.Network == UDP {
		return s.dialUDP(ctx)
	}
	gd := &netguard.Dialer{
		Resolver: s.cfg.Resolver,
		Allow:    append([]netip.Prefix(nil), s.cfg.AllowedCIDRs...),
		Timeout:  s.cfg.DialTimeout,
	}
	if s.cfg.Network == TCP {
		return gd.DialContext(ctx, "tcp", s.cfg.Address)
	}
	host, _, _ := net.SplitHostPort(s.cfg.Address)
	name := s.cfg.ServerName
	if name == "" {
		name = host
	}
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    s.cfg.RootCAs,
		ServerName: name,
	}
	if s.cfg.ClientCert != nil {
		tc.Certificates = []tls.Certificate{*s.cfg.ClientCert}
	}
	raw, err := gd.DialContext(ctx, "tcp", s.cfg.Address)
	if err != nil {
		return nil, err
	}
	tconn := tls.Client(raw, tc)
	if err := tconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tconn, nil
}

// dialUDP applies the same egress policy to a datagram destination
// (netguard.Dialer is TCP only).
func (s *Sender) dialUDP(ctx context.Context) (net.Conn, error) {
	host, port, err := net.SplitHostPort(s.cfg.Address)
	if err != nil {
		return nil, netguard.ErrBlockedDestination
	}
	var ips []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ips = []netip.Addr{ip}
	} else if ips, err = s.cfg.Resolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, ErrDelivery
	}
	if len(ips) == 0 {
		return nil, netguard.ErrBlockedDestination
	}
	for _, ip := range ips {
		if !netguard.AllowedIP(ip, s.cfg.AllowedCIDRs) {
			return nil, netguard.ErrBlockedDestination
		}
	}
	d := net.Dialer{Timeout: s.cfg.DialTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !netguard.AllowedIP(ap.Addr(), s.cfg.AllowedCIDRs) {
			return netguard.ErrBlockedDestination
		}
		return nil
	}}
	return d.DialContext(ctx, "udp", net.JoinHostPort(ips[0].Unmap().String(), port))
}
