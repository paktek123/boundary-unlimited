// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package httpsink

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/event/sinkqueue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeToken = "fake-token-0123456789"

var _ sinkqueue.Sender = (*Sender)(nil)

func loopbackCfg(t *testing.T, srv *httptest.Server, f Format) Config {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return Config{
		Format: f, URL: srv.URL + "/services/collector", Token: []byte(fakeToken),
		RootCAs: pool, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Timeout: 2 * time.Second,
	}
}

func TestSend_HEC(t *testing.T) {
	var gotBody, gotAuth, gotCT string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotAuth, gotCT = string(b), r.Header.Get("Authorization"), r.Header.Get("Content-Type")
	}))
	defer srv.Close()
	s, err := New(loopbackCfg(t, srv, FormatHEC))
	require.NoError(t, err)
	require.NoError(t, s.Send(context.Background(), [][]byte{[]byte(`{"a":1}`), []byte(`{"b":2}`)}))
	assert.Equal(t, `{"event":{"a":1}}{"event":{"b":2}}`, gotBody)
	assert.Equal(t, "Splunk "+fakeToken, gotAuth)
	assert.Equal(t, "application/json", gotCT)
}

func TestSend_JSON(t *testing.T) {
	var gotBody, gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotAuth = string(b), r.Header.Get("Authorization")
	}))
	defer srv.Close()
	s, err := New(loopbackCfg(t, srv, FormatJSON))
	require.NoError(t, err)
	require.NoError(t, s.Send(context.Background(), [][]byte{[]byte(`{"a":1}`), []byte(`{"b":2}`)}))
	assert.Equal(t, `[{"a":1},{"b":2}]`, gotBody)
	assert.Equal(t, "Bearer "+fakeToken, gotAuth)
	require.NoError(t, s.Send(context.Background(), nil))
}

func TestSend_Failures(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	for name, status := range map[string]int{"500": 500, "403": 403, "redirect": 307} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if status == 307 {
					w.Header().Set("Location", target.URL)
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte("CANARY-BODY"))
			}))
			defer srv.Close()
			s, err := New(loopbackCfg(t, srv, FormatHEC))
			require.NoError(t, err)
			err = s.Send(context.Background(), [][]byte{[]byte(`{}`)})
			require.ErrorIs(t, err, ErrDelivery)
			assert.NotContains(t, err.Error(), "CANARY")
			assert.NotContains(t, err.Error(), fakeToken)
		})
	}
	assert.Zero(t, redirected.Load(), "redirects are never followed")
}

func TestSend_InvalidEntryAndOversize(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	s, err := New(loopbackCfg(t, srv, FormatJSON))
	require.NoError(t, err)
	assert.ErrorIs(t, s.Send(context.Background(), [][]byte{[]byte("not json CANARY")}), ErrDelivery)
	big := []byte(`"` + strings.Repeat("a", MaxBodyBytes) + `"`)
	assert.ErrorIs(t, s.Send(context.Background(), [][]byte{big}), ErrDelivery)
}

// Without an allow-list a loopback collector is refused at dial time.
func TestSend_BlockedByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("must not be reached") }))
	defer srv.Close()
	cfg := loopbackCfg(t, srv, FormatHEC)
	cfg.AllowedCIDRs = nil
	s, err := New(cfg)
	require.NoError(t, err)
	assert.ErrorIs(t, s.Send(context.Background(), [][]byte{[]byte(`{}`)}), ErrDelivery)
}

func TestNew_Rejects(t *testing.T) {
	ok := Config{Format: FormatHEC, URL: "https://collector.example.com/x", Token: []byte(fakeToken)}
	_, err := New(ok)
	require.NoError(t, err)
	tests := map[string]func(*Config){
		"unknown format": func(c *Config) { c.Format = "xml" },
		"empty format":   func(c *Config) { c.Format = "" },
		"http":           func(c *Config) { c.URL = "http://collector.example.com/x" },
		"userinfo":       func(c *Config) { c.URL = "https://u:p@collector.example.com/x" },
		"fragment":       func(c *Config) { c.URL = "https://collector.example.com/x#f" },
		"no host":        func(c *Config) { c.URL = "https:///x" },
		"short token":    func(c *Config) { c.Token = []byte("x") },
		"token newline":  func(c *Config) { c.Token = []byte("fake-token-01\nX-Evil: 1") },
		"neg timeout":    func(c *Config) { c.Timeout = -1 },
		"huge timeout":   func(c *Config) { c.Timeout = time.Hour },
		"bad cidr":       func(c *Config) { c.AllowedCIDRs = []netip.Prefix{{}} },
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			c := ok
			mut(&c)
			_, err := New(c)
			require.ErrorIs(t, err, ErrInvalidConfig)
			assert.NotContains(t, err.Error(), fakeToken)
		})
	}
}

func TestRedaction(t *testing.T) {
	s, err := New(Config{Format: FormatHEC, URL: "https://collector.example.com/CANARYPATH", Token: []byte(fakeToken)})
	require.NoError(t, err)
	for _, v := range []string{s.String(), s.GoString()} {
		assert.NotContains(t, v, "CANARYPATH")
		assert.NotContains(t, v, fakeToken)
	}
}
