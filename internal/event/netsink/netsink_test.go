// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package netsink

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	_, err := New(&event.SinkConfig{Type: event.SyslogSink}, Deps{})
	require.ErrorIs(t, err, ErrUnsupported)
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
