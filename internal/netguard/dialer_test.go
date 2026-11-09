// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func TestBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", "169.254.0.1", "fe80::1", "fd00:ec2::254", "fc00::1",
		"0.0.0.0", "::", "224.0.0.1", "ff02::1", "100.64.0.1", "100.100.100.200",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::7f00:1", "2002:7f00:1::1",
		"240.0.0.1", "192.0.0.8",
	}
	for _, s := range blocked {
		assert.True(t, BlockedIP(netip.MustParseAddr(s)), s)
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		assert.False(t, BlockedIP(netip.MustParseAddr(s)), s)
	}
	assert.True(t, BlockedIP(netip.Addr{}))
}

func TestDialerRejectsBlockedAddresses(t *testing.T) {
	res := fakeResolver{
		"loop.example":    {netip.MustParseAddr("127.0.0.1")},
		"meta.example":    {netip.MustParseAddr("169.254.169.254")},
		"private.example": {netip.MustParseAddr("10.0.0.5")},
		"mixed.example":   {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.5")},
		"empty.example":   {},
	}
	d := &Dialer{Resolver: res, Timeout: time.Second}
	for _, addr := range []string{
		"loop.example:443", "meta.example:443", "private.example:443", "mixed.example:443", "empty.example:443",
		"127.0.0.1:443", "169.254.169.254:80", "[::1]:443", "10.0.0.5:443", "[::ffff:10.0.0.5]:443",
		"nohost-without-port",
	} {
		_, err := d.DialContext(context.Background(), "tcp", addr)
		assert.ErrorIs(t, err, ErrBlockedDestination, addr)
	}
	_, err := d.DialContext(context.Background(), "unix", "/tmp/x")
	assert.ErrorIs(t, err, ErrBlockedDestination)

	// A failed lookup is an error, not a bypass.
	_, err = d.DialContext(context.Background(), "tcp", "unknown.example:443")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrBlockedDestination)
}

func TestDialerControlRechecksActualAddress(t *testing.T) {
	d := &Dialer{}
	assert.ErrorIs(t, d.control("tcp", "127.0.0.1:443", nil), ErrBlockedDestination)
	assert.ErrorIs(t, d.control("tcp", "[::1]:443", nil), ErrBlockedDestination)
	assert.ErrorIs(t, d.control("tcp", "garbage", nil), ErrBlockedDestination)
	assert.NoError(t, d.control("tcp", "8.8.8.8:443", nil))
}

func TestDialerAllowlistIsExplicitOptIn(t *testing.T) {
	// Listen on loopback; only an allowlist covering it lets the dial through.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, err = (&Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", ln.Addr().String())
	assert.ErrorIs(t, err, ErrBlockedDestination)

	d := &Dialer{Timeout: time.Second, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	c, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	c.Close()
}
