// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package netguard holds the SSRF-safe dialer shared by every component that
// connects to an operator-configured destination (webhooks and chat senders in
// internal/notify, and later audit sinks and the external authorizer). There is
// exactly one audited implementation: it resolves the host, refuses the lookup
// if any answer is a loopback, private, link-local (including the metadata
// address), unspecified, multicast or special-purpose address unless an
// explicit allowed prefix covers it, and re-checks the address actually
// connected to so DNS rebinding cannot reach a blocked address.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// ErrBlockedDestination is returned when a destination address is not
// permitted. The error never includes the host or address.
var ErrBlockedDestination = errors.New("netguard: destination address is not permitted")

// Resolver resolves host names. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this" network
	"100.64.0.0/10",   // carrier-grade NAT (includes some cloud metadata addresses)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved
	"64:ff9b::/96",    // NAT64: can embed any IPv4 address
	"64:ff9b:1::/48",  // local-use NAT64
	"2002::/16",       // 6to4: can embed any IPv4 address
	"100::/64",        // discard-only
	"2001:db8::/32",   // documentation
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s))
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// BlockedIP reports whether ip is never a valid destination by
// default: loopback, link-local (including the 169.254.169.254 metadata
// address), private (RFC 1918 and unique-local IPv6), unspecified, multicast
// and other special-purpose ranges.
func BlockedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowedIP applies the block list and the explicit per-notifier allowlist.
func AllowedIP(ip netip.Addr, allow []netip.Prefix) bool {
	ip = ip.Unmap()
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	return !BlockedIP(ip)
}

// Dialer resolves the host, rejects the lookup if any returned address is
// not permitted, dials only the validated addresses and re-checks the address
// actually connected to, so a DNS answer changing between check and use cannot
// reach a blocked address.
type Dialer struct {
	// Resolver resolves host names; nil refuses every non-literal host.
	Resolver Resolver
	// Allow is the explicit opt-in allowlist; empty by default.
	Allow []netip.Prefix
	// Timeout bounds one connection attempt.
	Timeout time.Duration
}

func (d *Dialer) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !AllowedIP(ap.Addr(), d.Allow) {
		return ErrBlockedDestination
	}
	return nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, ErrBlockedDestination
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrBlockedDestination
	}
	var ips []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ips = []netip.Addr{ip}
	} else {
		if d.Resolver == nil {
			return nil, ErrBlockedDestination
		}
		ips, err = d.Resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("netguard: resolve destination: %w", errResolve)
		}
	}
	if len(ips) == 0 {
		return nil, ErrBlockedDestination
	}
	for _, ip := range ips {
		if !AllowedIP(ip, d.Allow) {
			return nil, ErrBlockedDestination
		}
	}
	nd := &net.Dialer{Timeout: d.Timeout, Control: d.control}
	var lastErr error
	for _, ip := range ips {
		conn, derr := nd.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if derr == nil {
			return conn, nil
		}
		if errors.Is(derr, ErrBlockedDestination) {
			return nil, ErrBlockedDestination
		}
		lastErr = derr
	}
	_ = lastErr // dial errors can contain the address; never returned
	return nil, errDial
}

var (
	errResolve = errors.New("lookup failed")
	errDial    = errors.New("netguard: could not connect to destination")
)
