// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package syslogsink_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/event/sinkqueue"
	"github.com/hashicorp/boundary/internal/event/syslogfmt"
	"github.com/hashicorp/boundary/internal/event/syslogsink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ sinkqueue.Sender = (*syslogsink.Sender)(nil)

// loopback opts the test listeners into the egress guard's allowlist.
var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

func msg(text string) syslogfmt.Message {
	return syslogfmt.Message{
		Facility: syslogfmt.FacilityLocal0, Severity: syslogfmt.SevNotice,
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Hostname:  "host1", AppName: "boundary", ProcID: "42", MsgID: "audit", Msg: text,
	}
}

// readOctetCounted reads n octet-counted frames. It returns an error instead
// of failing the test so it is safe to call from a spawned goroutine.
func readOctetCounted(r *bufio.Reader, n int) ([]string, error) {
	var out []string
	for i := 0; i < n; i++ {
		l, err := r.ReadString(' ')
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(strings.TrimSuffix(l, " "))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size)
		if _, err = io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		out = append(out, string(buf))
	}
	return out, nil
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  syslogsink.Config
	}{
		{"empty", syslogsink.Config{}},
		{"unknown network", syslogsink.Config{Network: "sctp", Address: "h:1"}},
		{"no port", syslogsink.Config{Network: syslogsink.TCP, Address: "host"}},
		{"no host", syslogsink.Config{Network: syslogsink.TCP, Address: ":514"}},
		{"negative timeout", syslogsink.Config{Network: syslogsink.TCP, Address: "h:1", DialTimeout: -1}},
		{"tls option on tcp", syslogsink.Config{Network: syslogsink.TCP, Address: "h:1", ServerName: "x"}},
		{"tls option on udp", syslogsink.Config{Network: syslogsink.UDP, Address: "h:1", RootCAs: x509.NewCertPool()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := syslogsink.New(tt.cfg)
			require.ErrorIs(t, err, syslogsink.ErrInvalidConfig)
		})
	}
	_, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TLS, Address: "h:6514"})
	require.NoError(t, err)
}

func TestTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	type result struct {
		frames []string
		err    error
	}
	got := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- result{err: err}
			return
		}
		defer c.Close()
		f, err := readOctetCounted(bufio.NewReader(c), 2)
		got <- result{f, err}
	}()
	s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TCP, AllowedCIDRs: loopback, Address: ln.Addr().String()})
	require.NoError(t, err)
	f1, err := s.Frame(msg("one"))
	require.NoError(t, err)
	f2, err := s.Frame(msg("two"))
	require.NoError(t, err)
	require.NoError(t, s.Send(context.Background(), [][]byte{f1, f2}))
	select {
	case res := <-got:
		require.NoError(t, res.err)
		frames := res.frames
		require.Len(t, frames, 2)
		assert.Contains(t, frames[0], "one")
		assert.Contains(t, frames[1], "two")
		assert.Contains(t, frames[0], "2026-01-02T03:04:05.000000Z host1 boundary 42 audit")
		assert.True(t, strings.HasPrefix(frames[0], "<133>1 "), frames[0])
	case <-time.After(5 * time.Second):
		t.Fatal("no frames received")
	}
}

func TestUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()
	s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.UDP, AllowedCIDRs: loopback, Address: pc.LocalAddr().String()})
	require.NoError(t, err)
	f, err := s.Frame(msg("dgram"))
	require.NoError(t, err)
	assert.NotContains(t, string(f), "\n")
	require.NoError(t, s.Send(context.Background(), [][]byte{f}))
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, string(f), string(buf[:n]))
}

func TestSendFailures(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	ln.Close() // nothing listens any more
	s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TCP, AllowedCIDRs: loopback, Address: addr, DialTimeout: time.Second})
	require.NoError(t, err)
	err = s.Send(context.Background(), [][]byte{[]byte("x")})
	require.ErrorIs(t, err, syslogsink.ErrDelivery)
	assert.NotContains(t, err.Error(), addr, "errors do not echo the address or the entry")

	require.NoError(t, s.Send(context.Background(), nil), "empty batch is a no-op")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, s.Send(ctx, [][]byte{[]byte("x")}), syslogsink.ErrDelivery)
}

// testCert makes a throwaway CA-less self-signed server certificate.
func testCert(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func tlsListener(t *testing.T, cert tls.Certificate, max uint16) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: max})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestTLS(t *testing.T) {
	cert, pool := testCert(t, "collector.test")
	ln := tlsListener(t, cert, tls.VersionTLS13)
	type result struct {
		frame string
		err   error
	}
	got := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- result{err: err}
			return
		}
		defer c.Close()
		f, err := readOctetCounted(bufio.NewReader(c), 1)
		if err != nil {
			got <- result{err: err}
			return
		}
		got <- result{frame: f[0]}
	}()

	s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TLS, AllowedCIDRs: loopback, Address: ln.Addr().String(), RootCAs: pool, ServerName: "collector.test"})
	require.NoError(t, err)
	f, err := s.Frame(msg("secure"))
	require.NoError(t, err)
	require.NoError(t, s.Send(context.Background(), [][]byte{f}))
	select {
	case res := <-got:
		require.NoError(t, res.err)
		assert.Contains(t, res.frame, "secure")
	case <-time.After(5 * time.Second):
		t.Fatal("no frame received")
	}
}

func TestTLSRefusals(t *testing.T) {
	cert, pool := testCert(t, "collector.test")

	t.Run("untrusted certificate", func(t *testing.T) {
		ln := tlsListener(t, cert, tls.VersionTLS13)
		go func() {
			c, err := ln.Accept()
			if err == nil {
				_, _ = io.Copy(io.Discard, c)
				c.Close()
			}
		}()
		s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TLS, AllowedCIDRs: loopback, Address: ln.Addr().String(), ServerName: "collector.test", DialTimeout: 2 * time.Second})
		require.NoError(t, err)
		require.ErrorIs(t, s.Send(context.Background(), [][]byte{[]byte("x")}), syslogsink.ErrDelivery)
	})
	t.Run("wrong server name", func(t *testing.T) {
		ln := tlsListener(t, cert, tls.VersionTLS13)
		go func() {
			c, err := ln.Accept()
			if err == nil {
				_, _ = io.Copy(io.Discard, c)
				c.Close()
			}
		}()
		s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TLS, AllowedCIDRs: loopback, Address: ln.Addr().String(), RootCAs: pool, ServerName: "other.test", DialTimeout: 2 * time.Second})
		require.NoError(t, err)
		require.ErrorIs(t, s.Send(context.Background(), [][]byte{[]byte("x")}), syslogsink.ErrDelivery)
	})
	t.Run("server limited to TLS 1.1 is refused", func(t *testing.T) {
		ln := tlsListener(t, cert, tls.VersionTLS11)
		go func() {
			c, err := ln.Accept()
			if err == nil {
				_, _ = io.Copy(io.Discard, c)
				c.Close()
			}
		}()
		s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TLS, AllowedCIDRs: loopback, Address: ln.Addr().String(), RootCAs: pool, ServerName: "collector.test", DialTimeout: 2 * time.Second})
		require.NoError(t, err)
		require.ErrorIs(t, s.Send(context.Background(), [][]byte{[]byte("x")}), syslogsink.ErrDelivery)
	})
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return f[host], nil
}

// The egress guard refuses loopback, private, link-local and metadata
// destinations (literal or resolved) on every network unless allow-listed, and
// no connection is attempted.
func TestEgressGuardRefusals(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	res := fakeResolver{
		"loop.test":     {netip.MustParseAddr("127.0.0.1")},
		"private.test":  {netip.MustParseAddr("10.1.2.3")},
		"metadata.test": {netip.MustParseAddr("169.254.169.254")},
		"mixed.test":    {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("192.168.1.1")},
	}
	for _, network := range []syslogsink.Network{syslogsink.TCP, syslogsink.UDP, syslogsink.TLS} {
		for _, host := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "[::1]", "loop.test", "private.test", "metadata.test", "mixed.test", "unknown.test"} {
			s, err := syslogsink.New(syslogsink.Config{Network: network, Address: net.JoinHostPort(strings.Trim(host, "[]"), port), Resolver: res, DialTimeout: time.Second})
			require.NoError(t, err)
			err = s.Send(context.Background(), [][]byte{[]byte("x")})
			require.ErrorIs(t, err, syslogsink.ErrDelivery, "%s %s", network, host)
		}
	}
	select {
	case <-accepted:
		t.Fatal("a refused destination was dialled")
	case <-time.After(100 * time.Millisecond):
	}
}

// A DNS answer that changes to a private address after configuration is
// refused, because the check runs on the resolved address at connect time.
func TestEgressGuardDNSChange(t *testing.T) {
	res := fakeResolver{"collector.test": {netip.MustParseAddr("8.8.8.8")}}
	s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TCP, Address: "collector.test:514", Resolver: res, DialTimeout: 200 * time.Millisecond})
	require.NoError(t, err)
	res["collector.test"] = []netip.Addr{netip.MustParseAddr("10.0.0.5")}
	require.ErrorIs(t, s.Send(context.Background(), [][]byte{[]byte("x")}), syslogsink.ErrDelivery)
}

func TestAllowedCIDRsValidation(t *testing.T) {
	for _, p := range []netip.Prefix{{}, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")} {
		_, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TCP, Address: "h:1", AllowedCIDRs: []netip.Prefix{p}})
		require.ErrorIs(t, err, syslogsink.ErrInvalidConfig)
	}
}
