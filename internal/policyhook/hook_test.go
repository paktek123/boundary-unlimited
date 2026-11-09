// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package policyhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fakeSecret = "fake-authorizer-secret-0123456789"

type recEmitter struct {
	mu  sync.Mutex
	err error
	evs []Event
}

func (r *recEmitter) Emit(_ context.Context, e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.evs = append(r.evs, e)
	return nil
}

func (r *recEmitter) events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.evs...)
}

func input() Input {
	return Input{
		PrincipalID: "u_1234567890", UserID: "u_1234567890", AccountID: "acctpw_1234567890",
		GroupIDs: []string{"g_1"}, RoleIDs: []string{"r_1"}, TargetID: "ttcp_1234567890", TargetType: "tcp",
		ScopeIDs: []string{"p_1", "o_1", "global"}, HostID: "hst_1", Action: "authorize-session",
		RequestTime: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), SourceIP: "198.51.100.7",
	}
}

func newHook(t *testing.T, h http.Handler, mut func(*Config)) (*Hook, *recEmitter, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	em := &recEmitter{}
	cfg := Config{AuthorizerID: "opa-1", URL: srv.URL, Secret: []byte(fakeSecret), Client: srv.Client(), Emitter: em}
	if mut != nil {
		mut(&cfg)
	}
	hk, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return hk, em, &calls
}

func reply(code int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	})
}

func TestAuthorize_Table(t *testing.T) {
	tests := []struct {
		name   string
		h      http.Handler
		mut    func(*Config)
		want   Decision
		reason Reason
	}{
		{"allow", reply(200, `{"allow":true}`), nil, Allow, ReasonAllow},
		{"deny", reply(200, `{"allow":false}`), nil, Deny, ReasonDeny},
		{"500", reply(500, `{"allow":true}`), nil, Deny, ReasonError},
		{"403", reply(403, `{"allow":true}`), nil, Deny, ReasonError},
		{"redirect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/x", http.StatusFound) }), nil, Deny, ReasonError},
		{"malformed json", reply(200, `{"allow":`), nil, Deny, ReasonInvalidResponse},
		{"empty body", reply(200, ``), nil, Deny, ReasonInvalidResponse},
		{"allow missing", reply(200, `{"other":true}`), nil, Deny, ReasonInvalidResponse},
		{"allow as string", reply(200, `{"allow":"true"}`), nil, Deny, ReasonInvalidResponse},
		{"allow as number", reply(200, `{"allow":1}`), nil, Deny, ReasonInvalidResponse},
		{"allow null", reply(200, `{"allow":null}`), nil, Deny, ReasonInvalidResponse},
		{"array body", reply(200, `[true]`), nil, Deny, ReasonInvalidResponse},
		{"oversized", reply(200, `{"allow":true,"pad":"`+strings.Repeat("a", MaxResponseBytes)+`"}`), nil, Deny, ReasonInvalidResponse},
		{"timeout", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		}), func(c *Config) { c.Timeout = 50 * time.Millisecond }, Deny, ReasonTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hk, em, _ := newHook(t, tt.h, tt.mut)
			d, r := hk.Authorize(context.Background(), "req_1", true, input())
			if d != tt.want || r != tt.reason {
				t.Fatalf("got %v/%s, want %v/%s", d, r, tt.want, tt.reason)
			}
			evs := em.events()
			if len(evs) != 1 || evs[0].Reason != tt.reason || evs[0].Decision != tt.want || evs[0].AuthorizerID != "opa-1" {
				t.Fatalf("events: %+v", evs)
			}
		})
	}
}

func TestAuthorize_AuthorizerCannotWidenAccess(t *testing.T) {
	hk, em, calls := newHook(t, reply(200, `{"allow":true}`), nil)
	d, r := hk.Authorize(context.Background(), "req_1", false, input())
	if d != Deny || r != ReasonGrantsDeny {
		t.Fatalf("got %v/%s", d, r)
	}
	if atomic.LoadInt32(calls) != 0 {
		t.Fatal("authorizer must not be consulted when grants deny")
	}
	if len(em.events()) != 1 {
		t.Fatal("grants-deny must still be audited")
	}
}

func TestAuthorize_UnauditableAllowIsDenied(t *testing.T) {
	hk, em, _ := newHook(t, reply(200, `{"allow":true}`), nil)
	em.err = errors.New("sink down " + fakeSecret)
	if d, _ := hk.Authorize(context.Background(), "req_1", true, input()); d != Deny {
		t.Fatal("an allow that cannot be audited must be denied")
	}
	if d, _ := hk.Authorize(context.Background(), "", true, input()); d != Deny {
		t.Fatal("missing request id must be denied")
	}
}

func TestAuthorize_AllowNeverCachedDenyCachedUntilTTL(t *testing.T) {
	now := time.Unix(1700000000, 0)
	clock := func() time.Time { return now }

	// ALLOW is never cached, even with caching enabled.
	hk, _, calls := newHook(t, reply(200, `{"allow":true}`), func(c *Config) { c.CacheTTL = 5 * time.Second; c.Now = clock })
	for i := 0; i < 3; i++ {
		if d, _ := hk.Authorize(context.Background(), "req", true, input()); d != Allow {
			t.Fatal("want allow")
		}
	}
	if got := atomic.LoadInt32(calls); got != 3 {
		t.Fatalf("allow was served from cache: %d calls", got)
	}

	// DENY is cached until the TTL.
	hk, _, calls = newHook(t, reply(200, `{"allow":false}`), func(c *Config) { c.CacheTTL = 5 * time.Second; c.Now = clock })
	for i := 0; i < 3; i++ {
		hk.Authorize(context.Background(), "req", true, input())
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("deny should be cached: %d calls", got)
	}
	now = now.Add(5 * time.Second)
	hk.Authorize(context.Background(), "req", true, input())
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("deny cache entry should expire at ttl: %d calls", got)
	}
	// A different input is a different key.
	in := input()
	in.TargetID = "ttcp_other"
	hk.Authorize(context.Background(), "req", true, in)
	if got := atomic.LoadInt32(calls); got != 3 {
		t.Fatalf("cache key must cover the full input: %d calls", got)
	}

	// Cache is off by default.
	hk, _, calls = newHook(t, reply(200, `{"allow":false}`), nil)
	hk.Authorize(context.Background(), "req", true, input())
	hk.Authorize(context.Background(), "req", true, input())
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("cache must be off by default: %d calls", got)
	}
}

func TestNew_RejectsBadConfig(t *testing.T) {
	good := Config{AuthorizerID: "a", URL: "https://authz.invalid/v1/allow", Client: &http.Client{Transport: http.DefaultTransport}, Emitter: &recEmitter{}}
	tests := map[string]func(*Config){
		"http url":      func(c *Config) { c.URL = "http://authz.invalid/x" },
		"user info":     func(c *Config) { c.URL = "https://u:p@authz.invalid/x" },
		"no host":       func(c *Config) { c.URL = "https:///x" },
		"fragment":      func(c *Config) { c.URL = "https://authz.invalid/x#f" },
		"no client":     func(c *Config) { c.Client = nil },
		"no transport":  func(c *Config) { c.Client = &http.Client{} },
		"no emitter":    func(c *Config) { c.Emitter = nil },
		"no id":         func(c *Config) { c.AuthorizerID = "" },
		"timeout cap":   func(c *Config) { c.Timeout = MaxTimeout + 1 },
		"negative":      func(c *Config) { c.Timeout = -1 },
		"cache ttl cap": func(c *Config) { c.CacheTTL = MaxCacheTTL + 1 },
	}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			c := good
			mut(&c)
			_, err := New(c)
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), "authz.invalid") {
				t.Fatalf("error leaks url: %v", err)
			}
		})
	}
}

func TestCanary_NoSecretInOutputs(t *testing.T) {
	hk, em, _ := newHook(t, reply(500, "boom "+fakeSecret), nil)
	hk.Authorize(context.Background(), "req_1", true, input())
	cfg := Config{AuthorizerID: "a", URL: "https://authz.invalid/" + fakeSecret, Secret: []byte(fakeSecret)}
	outs := []string{fmt.Sprintf("%v %+v %#v", hk, hk, hk), fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), fmt.Sprintf("%+v", em.events())}
	for _, o := range outs {
		if strings.Contains(o, fakeSecret) || strings.Contains(o, "127.0.0.1") {
			t.Fatalf("leak in %q", o)
		}
	}
}

func TestZeroDecisionIsDeny(t *testing.T) {
	var d Decision
	if d != Deny {
		t.Fatal("zero value must be Deny")
	}
	var h *Hook
	if d, _ := h.Authorize(context.Background(), "r", true, input()); d != Deny {
		t.Fatal("nil hook must deny")
	}
}
