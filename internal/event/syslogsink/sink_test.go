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

func msg(text string) syslogfmt.Message {
	return syslogfmt.Message{
		Facility: syslogfmt.FacilityLocal0, Severity: syslogfmt.SevNotice,
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Hostname:  "host1", AppName: "boundary", ProcID: "42", MsgID: "audit", Msg: text,
	}
}

// readOctetCounted reads n octet-counted frames.
func readOctetCounted(t *testing.T, r *bufio.Reader, n int) []string {
	t.Helper()
	var out []string
	for i := 0; i < n; i++ {
		l, err := r.ReadString(' ')
		require.NoError(t, err)
		size, err := strconv.Atoi(strings.TrimSuffix(l, " "))
		require.NoError(t, err)
		buf := make([]byte, size)
		_, err = io.ReadFull(r, buf)
		require.NoError(t, err)
		out = append(out, string(buf))
	}
	return out
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
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got <- readOctetCounted(t, bufio.NewReader(c), 2)
	}()
	s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TCP, Address: ln.Addr().String()})
	require.NoError(t, err)
	f1, err := s.Frame(msg("one"))
	require.NoError(t, err)
	f2, err := s.Frame(msg("two"))
	require.NoError(t, err)
	require.NoError(t, s.Send(context.Background(), [][]byte{f1, f2}))
	select {
	case frames := <-got:
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
	s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.UDP, Address: pc.LocalAddr().String()})
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
	s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TCP, Address: addr, DialTimeout: time.Second})
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
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got <- readOctetCounted(t, bufio.NewReader(c), 1)[0]
	}()

	s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TLS, Address: ln.Addr().String(), RootCAs: pool, ServerName: "collector.test"})
	require.NoError(t, err)
	f, err := s.Frame(msg("secure"))
	require.NoError(t, err)
	require.NoError(t, s.Send(context.Background(), [][]byte{f}))
	select {
	case fr := <-got:
		assert.Contains(t, fr, "secure")
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
		s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TLS, Address: ln.Addr().String(), ServerName: "collector.test", DialTimeout: 2 * time.Second})
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
		s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TLS, Address: ln.Addr().String(), RootCAs: pool, ServerName: "other.test", DialTimeout: 2 * time.Second})
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
		s, err := syslogsink.New(syslogsink.Config{Network: syslogsink.TLS, Address: ln.Addr().String(), RootCAs: pool, ServerName: "collector.test", DialTimeout: 2 * time.Second})
		require.NoError(t, err)
		require.ErrorIs(t, s.Send(context.Background(), [][]byte{[]byte("x")}), syslogsink.ErrDelivery)
	})
}
