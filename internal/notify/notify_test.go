// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const canarySecret = "canary-secret-0123456789"

func testEvent() Event {
	return Event{
		Type:      "access_request.created",
		RequestID: "ar_1234567890",
		ScopeID:   "p_1234567890",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Summary:   "alice requested access",
	}
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

// newTestNotifier points a notifier for https://example.com at the TLS test
// server through the test-only dial hook; production defaults are untouched.
func newTestNotifier(t *testing.T, srv *httptest.Server, mod func(*WebhookConfig)) *WebhookNotifier {
	t.Helper()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	cfg := WebhookConfig{URL: "https://example.com:" + port + "/hook", Secret: []byte(canarySecret)}
	if mod != nil {
		mod(&cfg)
	}
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	w, err := newWebhook(cfg, hooks{
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		},
		rootCAs: pool,
		sleep:   func(context.Context, time.Duration) error { return nil },
	})
	require.NoError(t, err)
	return w
}

func TestSignAndDelivery(t *testing.T) {
	var gotBody []byte
	var gotSig, gotTS string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig, gotTS = r.Header.Get(SignatureHeader), r.Header.Get(TimestampHeader)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	w := newTestNotifier(t, srv, nil)
	require.NoError(t, w.Notify(context.Background(), testEvent()))

	ts, err := strconv.ParseInt(gotTS, 10, 64)
	require.NoError(t, err)
	assert.True(t, Verify([]byte(canarySecret), ts, gotBody, gotSig))
	assert.False(t, Verify([]byte(canarySecret), ts+1, gotBody, gotSig), "timestamp change must break the signature")
	assert.False(t, Verify([]byte(canarySecret), ts, append([]byte("x"), gotBody...), gotSig), "body change must break the signature")
	assert.False(t, Verify([]byte("another-secret-0123456"), ts, gotBody, gotSig))
	assert.NotContains(t, string(gotBody), canarySecret)
	assert.Contains(t, string(gotBody), `"request_id":"ar_1234567890"`)
}

func TestRetries(t *testing.T) {
	tests := []struct {
		name     string
		statuses []int
		wantErr  error
		wantHits int32
	}{
		{"success first try", []int{200}, nil, 1},
		{"5xx then success", []int{503, 200}, nil, 2},
		{"always 5xx is bounded", []int{500, 500, 500, 500, 500}, ErrDelivery, 3},
		{"4xx is not retried", []int{400, 200}, ErrRejected, 1},
		{"429 is not retried", []int{429, 200}, ErrRejected, 1},
		{"3xx is not retried", []int{302, 200}, ErrRedirect, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hits int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				i := int(atomic.AddInt32(&hits, 1)) - 1
				if i >= len(tt.statuses) {
					i = len(tt.statuses) - 1
				}
				if tt.statuses[i] == 302 {
					rw.Header().Set("Location", "https://10.0.0.1/internal")
				}
				rw.WriteHeader(tt.statuses[i])
			}))
			defer srv.Close()
			w := newTestNotifier(t, srv, nil)
			err := w.Notify(context.Background(), testEvent())
			if tt.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tt.wantErr)
			}
			assert.Equal(t, tt.wantHits, atomic.LoadInt32(&hits))
		})
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var privateHits int32
	private := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&privateHits, 1)
	}))
	defer private.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, private.URL, http.StatusFound)
	}))
	defer srv.Close()
	w := newTestNotifier(t, srv, nil)
	require.ErrorIs(t, w.Notify(context.Background(), testEvent()), ErrRedirect)
	assert.Zero(t, atomic.LoadInt32(&privateHits))
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
		assert.True(t, blockedIP(netip.MustParseAddr(s)), s)
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		assert.False(t, blockedIP(netip.MustParseAddr(s)), s)
	}
	assert.True(t, blockedIP(netip.Addr{}))
}

func TestDialerRejectsBlockedAddresses(t *testing.T) {
	res := fakeResolver{
		"loop.example":    {netip.MustParseAddr("127.0.0.1")},
		"meta.example":    {netip.MustParseAddr("169.254.169.254")},
		"private.example": {netip.MustParseAddr("10.0.0.5")},
		"mixed.example":   {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.5")},
		"empty.example":   {},
	}
	d := &safeDialer{resolver: res, timeout: time.Second}
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
	d := &safeDialer{}
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
	_, err = (&safeDialer{timeout: time.Second}).DialContext(context.Background(), "tcp", ln.Addr().String())
	assert.ErrorIs(t, err, ErrBlockedDestination)

	d := &safeDialer{timeout: time.Second, allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	c, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	c.Close()
}

func TestProductionNotifierBlocksPrivateDestination(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { atomic.AddInt32(&hits, 1) }))
	defer srv.Close()
	// srv.URL is https://127.0.0.1:port; the production dialer must refuse it.
	w, err := NewWebhookNotifier(WebhookConfig{URL: srv.URL, Secret: []byte(canarySecret)})
	require.NoError(t, err)
	err = w.Notify(context.Background(), testEvent())
	require.ErrorIs(t, err, ErrBlockedDestination)
	assert.Zero(t, atomic.LoadInt32(&hits))

	w, err = NewWebhookNotifier(WebhookConfig{
		URL: "https://rebind.example/hook", Secret: []byte(canarySecret),
		Resolver: fakeResolver{"rebind.example": {netip.MustParseAddr("169.254.169.254")}},
	})
	require.NoError(t, err)
	require.ErrorIs(t, w.Notify(context.Background(), testEvent()), ErrBlockedDestination)
}

func TestConfigValidation(t *testing.T) {
	good := WebhookConfig{URL: "https://example.com/h", Secret: []byte(canarySecret)}
	tests := []struct {
		name string
		mod  func(*WebhookConfig)
	}{
		{"http scheme", func(c *WebhookConfig) { c.URL = "http://example.com/h" }},
		{"no scheme", func(c *WebhookConfig) { c.URL = "example.com/h" }},
		{"ftp scheme", func(c *WebhookConfig) { c.URL = "ftp://example.com/h" }},
		{"no host", func(c *WebhookConfig) { c.URL = "https:///h" }},
		{"userinfo", func(c *WebhookConfig) { c.URL = "https://u:p@example.com/h" }},
		{"fragment", func(c *WebhookConfig) { c.URL = "https://example.com/h#x" }},
		{"empty url", func(c *WebhookConfig) { c.URL = "" }},
		{"nil secret", func(c *WebhookConfig) { c.Secret = nil }},
		{"short secret", func(c *WebhookConfig) { c.Secret = []byte("short") }},
		{"negative timeout", func(c *WebhookConfig) { c.Timeout = -1 }},
		{"timeout above max", func(c *WebhookConfig) { c.Timeout = HardMaxTimeout + 1 }},
		{"attempts above max", func(c *WebhookConfig) { c.MaxAttempts = HardMaxAttempts + 1 }},
		{"negative attempts", func(c *WebhookConfig) { c.MaxAttempts = -1 }},
		{"backoff above max", func(c *WebhookConfig) { c.Backoff = HardMaxBackoff + 1 }},
		{"body above max", func(c *WebhookConfig) { c.MaxBodyBytes = HardMaxBodyBytes + 1 }},
		{"response above max", func(c *WebhookConfig) { c.MaxResponseBytes = HardMaxResponseBytes + 1 }},
		{"invalid cidr", func(c *WebhookConfig) { c.AllowedCIDRs = []netip.Prefix{{}} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := good
			tt.mod(&c)
			w, err := NewWebhookNotifier(c)
			require.ErrorIs(t, err, ErrInvalidConfig)
			assert.Nil(t, w)
			assert.NotContains(t, err.Error(), canarySecret)
		})
	}
	// at-max values are accepted
	c := good
	c.Timeout, c.MaxAttempts, c.Backoff = HardMaxTimeout, HardMaxAttempts, HardMaxBackoff
	c.MaxBodyBytes, c.MaxResponseBytes = HardMaxBodyBytes, HardMaxResponseBytes
	_, err := NewWebhookNotifier(c)
	require.NoError(t, err)
}

func TestEventValidationAndBodyLimit(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		t.Error("request must not be sent")
	}))
	defer srv.Close()
	w := newTestNotifier(t, srv, func(c *WebhookConfig) { c.MaxBodyBytes = 200 })

	big := testEvent()
	big.Summary = strings.Repeat("a", MaxSummaryLen)
	require.ErrorIs(t, w.Notify(context.Background(), big), ErrBodyTooLarge)

	bad := map[string]func(*Event){
		"empty type":    func(e *Event) { e.Type = "" },
		"upper type":    func(e *Event) { e.Type = "Access" },
		"long type":     func(e *Event) { e.Type = strings.Repeat("a", MaxEventTypeLen+1) },
		"no request id": func(e *Event) { e.RequestID = "" },
		"long scope id": func(e *Event) { e.ScopeID = strings.Repeat("a", MaxEventIDLen+1) },
		"zero time":     func(e *Event) { e.Timestamp = time.Time{} },
		"long summary":  func(e *Event) { e.Summary = strings.Repeat("a", MaxSummaryLen+1) },
		"control char":  func(e *Event) { e.Summary = "a\nb" },
		"bidi override": func(e *Event) { e.Summary = "a‮b" },
		"invalid utf8":  func(e *Event) { e.Summary = "a\xffb" },
	}
	for name, mod := range bad {
		e := testEvent()
		mod(&e)
		assert.ErrorIs(t, w.Notify(context.Background(), e), ErrInvalidEvent, name)
	}
}

func TestSecretAndURLNeverInErrors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	secretPath := "/services/T0000/B0000/URLCANARY"
	w := newTestNotifier(t, srv, func(c *WebhookConfig) { c.URL += secretPath })
	check := func(err error) {
		require.Error(t, err)
		for _, s := range []string{canarySecret, "URLCANARY", "example.com", "127.0.0.1"} {
			assert.NotContains(t, err.Error(), s)
		}
	}
	check(w.Notify(context.Background(), testEvent()))

	for _, s := range []string{fmt.Sprint(w), fmt.Sprintf("%#v", w), fmt.Sprintf("%+v", WebhookConfig{Secret: []byte(canarySecret)})} {
		assert.NotContains(t, s, canarySecret)
	}

	// transport error and blocked destination
	closed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	wc := newTestNotifier(t, closed, func(c *WebhookConfig) { c.URL += secretPath })
	closed.Close()
	check(wc.Notify(context.Background(), testEvent()))

	prod, err := NewWebhookNotifier(WebhookConfig{URL: "https://127.0.0.1" + secretPath, Secret: []byte(canarySecret)})
	require.NoError(t, err)
	check(prod.Notify(context.Background(), testEvent()))
}

func TestTimeoutBoundsCaller(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	w := newTestNotifier(t, srv, func(c *WebhookConfig) { c.Timeout = 150 * time.Millisecond })
	start := time.Now()
	err := w.Notify(context.Background(), testEvent())
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, w.Notify(ctx, testEvent()))
}

func TestNilAndZeroValues(t *testing.T) {
	var w *WebhookNotifier
	assert.NotPanics(t, func() { assert.Error(t, w.Notify(context.Background(), testEvent())) })
	z := &WebhookNotifier{}
	assert.NotPanics(t, func() { assert.Error(t, z.Notify(context.Background(), testEvent())) })
}

func TestResponseBodyIsCapped(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(strings.Repeat("x", 1<<20)))
	}))
	defer srv.Close()
	w := newTestNotifier(t, srv, func(c *WebhookConfig) { c.MaxResponseBytes = 1024 })
	require.NoError(t, w.Notify(context.Background(), testEvent()))
}
