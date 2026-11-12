// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package httpsink is the HTTPS transport for event sinks: Splunk HEC and a
// generic JSON webhook. It implements sinkqueue.Sender over entries that are
// JSON documents. Nothing in the event system selects it yet: there is no sink
// type or HCL option, so no configuration can turn it on.
//
// Security properties: https only, no userinfo, TLS 1.2 minimum with no option
// to skip verification, no redirects, no proxy from the environment, the
// netguard dialer (loopback, private, link-local and metadata addresses are
// refused unless explicitly allow-listed), a bounded response read, and errors
// that never carry the URL, token, entries or response body.
//
// Splunk HEC format (Format "hec"): the request body is the concatenation of
// one {"event":<entry>} object per entry, sent with
// "Authorization: Splunk <token>". Generic format (Format "json"): the body is
// a JSON array of the entries, sent with "Authorization: Bearer <token>".
package httpsink

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/hashicorp/boundary/internal/netguard"
)

// Format selects the request body format.
type Format string

// Formats.
const (
	FormatHEC  Format = "hec"
	FormatJSON Format = "json"
)

// Limits and defaults.
const (
	DefaultTimeout   = 10 * time.Second
	MaxTimeout       = 60 * time.Second
	MinTokenLen      = 8
	MaxBodyBytes     = 8 << 20
	maxResponseBytes = 4 << 10
)

// Errors. They never carry entry contents, the URL, the token or the body.
var (
	ErrInvalidConfig = errors.New("httpsink: invalid configuration")
	ErrDelivery      = errors.New("httpsink: delivery failed")
)

// Config configures a Sender.
type Config struct {
	Format Format
	// URL must be https without userinfo or fragment.
	URL string
	// Token is the resolved HEC token or bearer token (at least MinTokenLen
	// bytes). It is never printed.
	Token []byte
	// Timeout bounds one request; zero selects DefaultTimeout.
	Timeout time.Duration
	// RootCAs verifies the collector; nil uses the system roots.
	RootCAs *x509.CertPool
	// Resolver resolves the collector host; nil uses the system resolver.
	Resolver netguard.Resolver
	// AllowedCIDRs is the explicit opt-in allowlist of the guarded dialer.
	AllowedCIDRs []netip.Prefix
}

// Sender delivers batches of JSON entries over HTTPS.
type Sender struct {
	format Format
	url    string
	token  []byte
	client *http.Client
}

// String and GoString never print the URL or token.
func (*Sender) String() string   { return "httpsink.Sender{redacted}" }
func (*Sender) GoString() string { return "httpsink.Sender{redacted}" }

// New validates cfg.
func New(cfg Config) (*Sender, error) {
	switch cfg.Format {
	case FormatHEC, FormatJSON:
	default:
		return nil, fmt.Errorf("%w: unknown format", ErrInvalidConfig)
	}
	u, err := url.Parse(cfg.URL)
	switch {
	case err != nil || u == nil:
		return nil, fmt.Errorf("%w: url", ErrInvalidConfig)
	case u.Scheme != "https":
		return nil, fmt.Errorf("%w: url must use https", ErrInvalidConfig)
	case u.Hostname() == "", u.User != nil, u.Fragment != "", u.Opaque != "":
		return nil, fmt.Errorf("%w: url", ErrInvalidConfig)
	}
	if len(cfg.Token) < MinTokenLen {
		return nil, fmt.Errorf("%w: token too short", ErrInvalidConfig)
	}
	for _, c := range cfg.Token {
		if c < 0x21 || c > 0x7e {
			return nil, fmt.Errorf("%w: token has invalid characters", ErrInvalidConfig)
		}
	}
	timeout := cfg.Timeout
	switch {
	case timeout < 0 || timeout > MaxTimeout:
		return nil, fmt.Errorf("%w: timeout", ErrInvalidConfig)
	case timeout == 0:
		timeout = DefaultTimeout
	}
	for _, p := range cfg.AllowedCIDRs {
		if !p.IsValid() {
			return nil, fmt.Errorf("%w: allowed cidr", ErrInvalidConfig)
		}
	}
	var res netguard.Resolver = net.DefaultResolver
	if cfg.Resolver != nil {
		res = cfg.Resolver
	}
	d := &netguard.Dialer{Resolver: res, Allow: append([]netip.Prefix(nil), cfg.AllowedCIDRs...), Timeout: timeout}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &Sender{
		format: cfg.Format,
		url:    u.String(),
		token:  append([]byte(nil), cfg.Token...),
		client: &http.Client{
			Transport:     tr,
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// body builds the request body. Entries must be valid JSON documents.
func (s *Sender) body(batch [][]byte) ([]byte, error) {
	var buf bytes.Buffer
	if s.format == FormatJSON {
		buf.WriteByte('[')
	}
	for i, e := range batch {
		if !json.Valid(e) {
			return nil, fmt.Errorf("%w: entry is not valid json", ErrDelivery)
		}
		// Refuse before copying so one oversized entry is never buffered.
		if buf.Len()+len(e) > MaxBodyBytes {
			return nil, fmt.Errorf("%w: batch too large", ErrDelivery)
		}
		switch s.format {
		case FormatHEC:
			buf.WriteString(`{"event":`)
			buf.Write(e)
			buf.WriteByte('}')
		default:
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.Write(e)
		}
		if buf.Len() > MaxBodyBytes {
			return nil, fmt.Errorf("%w: batch too large", ErrDelivery)
		}
	}
	if s.format == FormatJSON {
		buf.WriteByte(']')
	}
	return buf.Bytes(), nil
}

// Send implements sinkqueue.Sender. It succeeds only on a 2xx response; any
// other outcome (including a redirect) is an error so the batcher retries or
// enforces the delivery guarantee.
func (s *Sender) Send(ctx context.Context, batch [][]byte) error {
	if len(batch) == 0 {
		return nil
	}
	b, err := s.body(batch)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(b))
	if err != nil {
		return ErrDelivery
	}
	req.Header.Set("Content-Type", "application/json")
	if s.format == FormatHEC {
		req.Header.Set("Authorization", "Splunk "+string(s.token))
	} else {
		req.Header.Set("Authorization", "Bearer "+string(s.token))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return ErrDelivery
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: status %d", ErrDelivery, resp.StatusCode)
	}
	return nil
}
