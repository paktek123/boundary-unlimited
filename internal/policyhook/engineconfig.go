// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package policyhook

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/netguard"
)

// ErrSecretUnavailable is returned when the secret reference cannot be
// resolved. It never carries the reference or the value.
var ErrSecretUnavailable = errors.New("policyhook: secret unavailable")

const (
	envPrefix        = "env://"
	filePrefix       = "file://"
	maxSecretFileLen = 4096
	// MinSecretLen is the shortest accepted bearer secret.
	MinSecretLen = 16
)

var (
	idRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	envNmRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// EngineConfig is the `policy_engine` controller configuration. SecretRef is
// an env://NAME or absolute file:// reference, never the secret itself.
type EngineConfig struct {
	AuthorizerID string
	URL          string
	SecretRef    string
	Timeout      time.Duration
	CacheTTL     time.Duration
}

func (EngineConfig) String() string   { return "policyhook.EngineConfig{redacted}" }
func (EngineConfig) GoString() string { return "policyhook.EngineConfig{redacted}" }
func (c EngineConfig) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, c.String())
}

// Validate checks the syntax without reading the secret. Errors never contain
// the URL or the secret reference.
func (c EngineConfig) Validate() error {
	if !idRe.MatchString(c.AuthorizerID) {
		return fmt.Errorf("%w: authorizer_id must match %s", ErrInvalidConfig, idRe)
	}
	// Reuse the hook's own URL/timeout/cache checks with placeholders for the
	// runtime-only fields.
	if _, err := New(Config{
		AuthorizerID: c.AuthorizerID, URL: c.URL, Timeout: c.Timeout, CacheTTL: c.CacheTTL,
		Client: &http.Client{Transport: http.DefaultTransport}, Emitter: nopEmitter{},
	}); err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(c.SecretRef, envPrefix):
		if !envNmRe.MatchString(strings.TrimPrefix(c.SecretRef, envPrefix)) {
			return fmt.Errorf("%w: secret env reference is malformed", ErrInvalidConfig)
		}
	case strings.HasPrefix(c.SecretRef, filePrefix):
		if !filepath.IsAbs(strings.TrimPrefix(c.SecretRef, filePrefix)) {
			return fmt.Errorf("%w: secret file reference must be an absolute path", ErrInvalidConfig)
		}
	default:
		return fmt.Errorf("%w: secret must be an env:// or file:// reference, inline secrets are not allowed", ErrInvalidConfig)
	}
	return nil
}

type nopEmitter struct{}

func (nopEmitter) Emit(context.Context, Event) error { return nil }

// ResolveSecret reads an env:// or file:// reference. Files are capped at
// maxSecretFileLen bytes and one trailing newline is trimmed.
func ResolveSecret(ref string) ([]byte, error) {
	switch {
	case strings.HasPrefix(ref, envPrefix):
		if v := os.Getenv(strings.TrimPrefix(ref, envPrefix)); v != "" {
			return []byte(v), nil
		}
	case strings.HasPrefix(ref, filePrefix):
		f, err := os.Open(strings.TrimPrefix(ref, filePrefix))
		if err != nil {
			return nil, ErrSecretUnavailable
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, maxSecretFileLen+1))
		if err == nil && len(b) <= maxSecretFileLen {
			return []byte(strings.TrimSuffix(string(b), "\n")), nil
		}
	}
	return nil, ErrSecretUnavailable
}

// BuildDeps are the runtime dependencies of Build.
type BuildDeps struct {
	// Emitter receives every decision (required).
	Emitter Emitter
	// Resolve reads the secret; nil selects ResolveSecret.
	Resolve func(ref string) ([]byte, error)
	// Resolver resolves the authorizer host; nil uses net.DefaultResolver.
	Resolver netguard.Resolver
}

// Build validates cfg, resolves the secret (at least MinSecretLen bytes) and
// returns a Hook whose transport is the netguard dialer with TLS 1.2+ and no
// proxy. Any failure is an error and the caller must not start (fail closed).
func Build(cfg EngineConfig, deps BuildDeps) (*Hook, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if deps.Emitter == nil {
		return nil, fmt.Errorf("%w: missing emitter", ErrInvalidConfig)
	}
	resolve := deps.Resolve
	if resolve == nil {
		resolve = ResolveSecret
	}
	secret, err := resolve(cfg.SecretRef)
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	if len(secret) < MinSecretLen {
		return nil, fmt.Errorf("%w: secret is shorter than %d bytes", ErrInvalidConfig, MinSecretLen)
	}
	var res netguard.Resolver = net.DefaultResolver
	if deps.Resolver != nil {
		res = deps.Resolver
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	d := &netguard.Dialer{Resolver: res, Timeout: timeout}
	client := &http.Client{Transport: guardedTransport(d, timeout)}
	return New(Config{
		AuthorizerID: cfg.AuthorizerID, URL: cfg.URL, Secret: secret, Timeout: cfg.Timeout,
		CacheTTL: cfg.CacheTTL, Client: client, Emitter: deps.Emitter,
	})
}

func guardedTransport(d *netguard.Dialer, timeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:                  nil, // proxy environment variables would bypass the dialer checks
		DialContext:            d.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 16 << 10,
	}
}
