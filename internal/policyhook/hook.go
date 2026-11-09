// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package policyhook

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Limits. Values above a maximum are rejected, never clamped.
const (
	DefaultTimeout   = 2 * time.Second
	MaxTimeout       = 5 * time.Second
	MaxCacheTTL      = 5 * time.Second
	MaxResponseBytes = 64 << 10
	MaxCacheEntries  = 1024
)

// Decision is the outcome of the hook. The zero value is DENY.
type Decision int

const (
	Deny Decision = iota
	Allow
)

func (d Decision) String() string {
	if d == Allow {
		return "allow"
	}
	return "deny"
}

// Reason is the audit reason code.
type Reason string

const (
	ReasonAllow           Reason = "allow"
	ReasonDeny            Reason = "deny"
	ReasonError           Reason = "error"
	ReasonTimeout         Reason = "timeout"
	ReasonInvalidResponse Reason = "invalid_response"
	// ReasonGrantsDeny is used when the built-in grants already denied; the
	// authorizer is not called.
	ReasonGrantsDeny Reason = "grants_deny"
)

// ErrInvalidConfig is returned by New. It carries neither URL nor secret.
var ErrInvalidConfig = errors.New("policyhook: invalid configuration")

// Input is the complete, typed input document. Adding a field is a reviewed
// change (see the RFC). It must never carry tokens, credentials, secrets,
// session keys or raw grant strings.
type Input struct {
	PrincipalID string    `json:"principal_id"`
	UserID      string    `json:"user_id"`
	AccountID   string    `json:"account_id"`
	GroupIDs    []string  `json:"group_ids"`
	RoleIDs     []string  `json:"role_ids"`
	TargetID    string    `json:"target_id"`
	TargetType  string    `json:"target_type"`
	ScopeIDs    []string  `json:"scope_ids"`
	HostID      string    `json:"host_id"`
	Action      string    `json:"action"`
	RequestTime time.Time `json:"request_time"`
	SourceIP    string    `json:"source_ip"`
}

// Event is the audit record of one decision. It never holds the input
// document, the response body or any secret.
type Event struct {
	RequestID    string
	PrincipalID  string
	TargetID     string
	AuthorizerID string
	Decision     Decision
	Reason       Reason
	Latency      time.Duration
}

// Emitter receives decision events.
type Emitter interface {
	Emit(ctx context.Context, e Event) error
}

// Config configures a Hook.
type Config struct {
	// AuthorizerID labels audit events. Required.
	AuthorizerID string
	// URL must be https with a host, no user info and no fragment.
	URL string
	// Secret is sent as a bearer token when non-empty. Never printed.
	Secret []byte
	// Timeout bounds one call; zero means DefaultTimeout, above MaxTimeout is
	// rejected.
	Timeout time.Duration
	// CacheTTL enables DENY-only caching when > 0 (at most MaxCacheTTL). Zero
	// (the default) disables caching.
	CacheTTL time.Duration
	// Client performs the request. Required, with a non-nil Transport that
	// uses the guarded dialer. Redirects are never followed (a copy is used).
	Client *http.Client
	// Emitter receives every decision. Required.
	Emitter Emitter
	// Now is for tests; nil uses time.Now.
	Now func() time.Time
}

// String and GoString never print the URL or secret.
func (Config) String() string   { return "policyhook.Config{redacted}" }
func (Config) GoString() string { return "policyhook.Config{redacted}" }

// Hook calls the external authorizer.
type Hook struct {
	id      string
	url     string
	secret  []byte
	timeout time.Duration
	ttl     time.Duration
	client  *http.Client
	em      Emitter
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]time.Time // DENY entries only: key -> expiry
}

// String and GoString never print the URL or secret.
func (*Hook) String() string   { return "policyhook.Hook{redacted}" }
func (*Hook) GoString() string { return "policyhook.Hook{redacted}" }

// New validates cfg.
func New(cfg Config) (*Hook, error) {
	u, err := url.Parse(cfg.URL)
	switch {
	case cfg.AuthorizerID == "", cfg.Client == nil, cfg.Client.Transport == nil, cfg.Emitter == nil:
		return nil, fmt.Errorf("%w: missing field", ErrInvalidConfig)
	case err != nil, u == nil, u.Scheme != "https", u.Hostname() == "", u.User != nil, u.Fragment != "", u.Opaque != "":
		return nil, fmt.Errorf("%w: url must be https", ErrInvalidConfig)
	case cfg.Timeout < 0 || cfg.Timeout > MaxTimeout:
		return nil, fmt.Errorf("%w: timeout", ErrInvalidConfig)
	case cfg.CacheTTL < 0 || cfg.CacheTTL > MaxCacheTTL:
		return nil, fmt.Errorf("%w: cache ttl", ErrInvalidConfig)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	c := *cfg.Client // copy: never mutate the caller's client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h := &Hook{
		id: cfg.AuthorizerID, url: u.String(), secret: append([]byte(nil), cfg.Secret...),
		timeout: timeout, ttl: cfg.CacheTTL, client: &c, em: cfg.Emitter, now: cfg.Now,
		cache: map[string]time.Time{},
	}
	if h.now == nil {
		h.now = time.Now
	}
	return h, nil
}

// Authorize returns the final decision: the AND of the built-in grants result
// and the authorizer. If grantsAllowed is false the authorizer is not called
// and the result is Deny. Any failure, including a failure to emit the audit
// event, yields Deny. The returned Reason is for the audit trail only; callers
// must show clients a generic "access denied".
func (h *Hook) Authorize(ctx context.Context, requestID string, grantsAllowed bool, in Input) (d Decision, r Reason) {
	start := h.nowSafe()
	defer func() {
		if recover() != nil {
			d, r = Deny, ReasonError
		}
		d, r = h.audit(ctx, requestID, in, d, r, h.nowSafe().Sub(start))
	}()
	if h == nil || !grantsAllowed {
		return Deny, ReasonGrantsDeny
	}
	key, err := cacheKey(in)
	if err != nil {
		return Deny, ReasonError
	}
	if h.cachedDeny(key) {
		return Deny, ReasonDeny
	}
	d, r = h.call(ctx, in)
	if d == Deny && r == ReasonDeny {
		h.storeDeny(key)
	}
	return d, r
}

func (h *Hook) nowSafe() time.Time {
	if h == nil || h.now == nil {
		return time.Now()
	}
	return h.now()
}

func (h *Hook) audit(ctx context.Context, requestID string, in Input, d Decision, r Reason, lat time.Duration) (Decision, Reason) {
	if h == nil || h.em == nil {
		return Deny, ReasonError
	}
	ev := Event{RequestID: requestID, PrincipalID: in.PrincipalID, TargetID: in.TargetID, AuthorizerID: h.id, Decision: d, Reason: r, Latency: lat}
	if requestID == "" || h.emit(ctx, ev) != nil {
		// An unauditable allow is not allowed.
		return Deny, ReasonError
	}
	return d, r
}

func (h *Hook) emit(ctx context.Context, ev Event) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("policyhook: emitter panic")
		}
	}()
	return h.em.Emit(ctx, ev)
}

func (h *Hook) call(ctx context.Context, in Input) (Decision, Reason) {
	body, err := json.Marshal(in)
	if err != nil {
		return Deny, ReasonError
	}
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return Deny, ReasonError
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if len(h.secret) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(h.secret))
	}
	resp, err := h.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Deny, ReasonTimeout
		}
		return Deny, ReasonError
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Deny, ReasonError
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return Deny, ReasonTimeout
		}
		return Deny, ReasonError
	}
	if len(b) > MaxResponseBytes {
		return Deny, ReasonInvalidResponse
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(b, &doc) != nil {
		return Deny, ReasonInvalidResponse
	}
	switch string(bytes.TrimSpace(doc["allow"])) { // only a literal JSON boolean counts
	case "true":
		return Allow, ReasonAllow
	case "false":
		return Deny, ReasonDeny
	}
	return Deny, ReasonInvalidResponse
}

func cacheKey(in Input) (string, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (h *Hook) cachedDeny(key string) bool {
	if h.ttl <= 0 {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	exp, ok := h.cache[key]
	if !ok {
		return false
	}
	if !h.now().Before(exp) {
		delete(h.cache, key)
		return false
	}
	return true
}

// storeDeny caches a DENY only. ALLOW never reaches this function.
func (h *Hook) storeDeny(key string) {
	if h.ttl <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if len(h.cache) >= MaxCacheEntries {
		for k, exp := range h.cache {
			if !now.Before(exp) {
				delete(h.cache, k)
			}
		}
		if len(h.cache) >= MaxCacheEntries {
			return // bounded: do not grow
		}
	}
	h.cache[key] = now.Add(h.ttl)
}
