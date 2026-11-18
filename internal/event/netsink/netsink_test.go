// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package netsink

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const canary = "CANARYTOKEN0123456789"

func okSecret(string) ([]byte, error) { return []byte(canary), nil }

func httpCfg(url string) *event.HTTPSinkTypeConfig {
	return &event.HTTPSinkTypeConfig{URL: url, Token: "env://SIEM_TOKEN", Format: event.HTTPFormatJSON, AllowPrivateCIDRs: []string{"127.0.0.0/8"}}
}

func TestNewHTTPDelivers(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var auth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies, auth = append(bodies, string(b)), r.Header.Get("Authorization")
		mu.Unlock()
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	s, err := NewHTTP(httpCfg(srv.URL+"/events"), Deps{ResolveSecret: okSecret, RootCAs: pool})
	require.NoError(t, err)
	n, err := s.Write([]byte(`{"id":"e1"}`))
	require.NoError(t, err)
	assert.Equal(t, len(`{"id":"e1"}`), n)
	require.NoError(t, s.Close(context.Background()))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, bodies, 1)
	assert.Contains(t, bodies[0], `"id":"e1"`)
	assert.Equal(t, "Bearer "+canary, auth)
	assert.EqualValues(t, 1, s.Sent())
	assert.EqualValues(t, 0, s.Dropped())
}

func TestNewHTTPFailsClosed(t *testing.T) {
	bad := map[string]struct {
		cfg  *event.HTTPSinkTypeConfig
		deps Deps
	}{
		"nil":               {nil, Deps{}},
		"invalid config":    {&event.HTTPSinkTypeConfig{URL: "http://siem.example.com/" + canary, Token: "env://X", Format: "json"}, Deps{ResolveSecret: okSecret}},
		"unresolvable":      {httpCfg("https://siem.example.com/" + canary), Deps{ResolveSecret: func(string) ([]byte, error) { return nil, errors.New("leaky " + canary) }}},
		"secret too short":  {httpCfg("https://siem.example.com/" + canary), Deps{ResolveSecret: func(string) ([]byte, error) { return []byte("x"), nil }}},
		"missing env value": {httpCfg("https://siem.example.com/" + canary), Deps{}},
	}
	for name, c := range bad {
		t.Run(name, func(t *testing.T) {
			s, err := NewHTTP(c.cfg, c.deps)
			require.Error(t, err)
			require.Nil(t, s)
			assert.ErrorIs(t, err, ErrBuild)
			assert.NotContains(t, err.Error(), canary)
			assert.NotContains(t, err.Error(), "siem.example.com")
		})
	}
}

// With the collector unreachable the producer is never blocked or errored.
func TestWriteNeverBlocksOrFails(t *testing.T) {
	s, err := NewHTTP(httpCfg("https://siem.example.com/x"), Deps{ResolveSecret: okSecret,
		Resolver: nxResolver{}})
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			_, err := s.Write([]byte(`{"id":"e"}`))
			assert.NoError(t, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("producer blocked")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = s.Close(ctx)
	assert.Equal(t, "netsink.Sink{redacted}", fmt.Sprint(s))
	assert.False(t, strings.Contains(fmt.Sprintf("%#v %+v", s, s), canary))
}

func TestNewDispatch(t *testing.T) {
	_, err := New(&event.SinkConfig{Type: event.StderrSink}, Deps{})
	require.ErrorIs(t, err, ErrUnsupported)
	_, err = New(&event.SinkConfig{Type: event.SyslogSink}, Deps{})
	require.ErrorIs(t, err, ErrBuild)
	_, err = New(nil, Deps{})
	require.ErrorIs(t, err, ErrBuild)
	_, err = New(&event.SinkConfig{Type: event.HTTPSink}, Deps{})
	require.ErrorIs(t, err, ErrBuild)
}

// nxResolver answers every lookup with a TEST-NET address, which the egress
// guard refuses, so every delivery attempt fails.
type nxResolver struct{}

func (nxResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}

func TestNewSyslogDeliversFramedEntry(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		got <- string(b)
	}()
	s, err := NewSyslog(&event.SyslogSinkTypeConfig{
		Network: event.SyslogNetworkTCP, InsecurePlaintext: true, Address: ln.Addr().String(),
		AllowPrivateCIDRs: []string{"127.0.0.0/8"},
	}, Deps{})
	require.NoError(t, err)
	_, err = s.Write([]byte(`{"id":"e1"}`))
	require.NoError(t, err)
	require.NoError(t, s.Close(context.Background()))
	select {
	case frame := <-got:
		assert.Contains(t, frame, `{"id":"e1"}`)
		assert.Contains(t, frame, " boundary ")
		assert.Regexp(t, `^\d+ <134>1 `, frame, "octet-counted, local0.info")
	case <-time.After(5 * time.Second):
		t.Fatal("nothing received")
	}
	assert.EqualValues(t, 0, s.Dropped())
}

func TestNewSyslogFailsClosed(t *testing.T) {
	dir := t.TempDir()
	notPEM := dir + "/ca.pem"
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate "+canary), 0o600))
	base := func() *event.SyslogSinkTypeConfig {
		return &event.SyslogSinkTypeConfig{Address: "logs.example.com:6514"}
	}
	bad := map[string]*event.SyslogSinkTypeConfig{
		"nil":                      nil,
		"plaintext without opt-in": {Network: event.SyslogNetworkTCP, Address: "logs.example.com:514"},
	}
	m := base()
	m.CAFile = "file://" + dir + "/missing.pem"
	bad["missing ca"] = m
	n := base()
	n.CAFile = "file://" + notPEM
	bad["ca without certificates"] = n
	k := base()
	k.ClientCertFile, k.ClientKeyFile = "file://"+notPEM, "file://"+notPEM
	bad["invalid client pair"] = k
	c := base()
	c.AllowPrivateCIDRs = []string{"not-a-cidr"}
	bad["non-numeric cidr"] = c
	w := base()
	w.ClientCertFile = "file://" + notPEM
	bad["client cert without key"] = w
	for name, cfg := range bad {
		t.Run(name, func(t *testing.T) {
			s, err := NewSyslog(cfg, Deps{})
			require.Error(t, err)
			require.Nil(t, s)
			require.ErrorIs(t, err, ErrBuild)
			assert.NotContains(t, err.Error(), canary)
			assert.NotContains(t, err.Error(), "logs.example.com")
			assert.NotContains(t, err.Error(), dir)
		})
	}
}

func TestSyslogUnframeableEntryIsCounted(t *testing.T) {
	s, err := NewSyslog(&event.SyslogSinkTypeConfig{
		Network: event.SyslogNetworkUDP, InsecurePlaintext: true, Address: "127.0.0.1:9",
		AllowPrivateCIDRs: []string{"127.0.0.0/8"},
	}, Deps{})
	require.NoError(t, err)
	n, err := s.Write(make([]byte, 10_000)) // larger than a UDP datagram
	require.NoError(t, err)
	assert.Equal(t, 10_000, n)
	assert.EqualValues(t, 1, s.Dropped())
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = s.Close(ctx)
}

func TestWriteAfterCloseIsCountedAsDropped(t *testing.T) {
	s, err := NewHTTP(httpCfg("https://logs.example.com/ingest"), Deps{ResolveSecret: okSecret})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.Close(ctx)
	before := s.Dropped()
	n, err := s.Write([]byte(`{"a":1}`))
	require.NoError(t, err)
	assert.Equal(t, 7, n)
	assert.Equal(t, before+1, s.Dropped())
}
