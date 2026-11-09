// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/hashicorp/boundary/internal/netguard"
)

// Hard limits. Configuration above a maximum is rejected, never clamped.
const (
	DefaultMaxBodyBytes     = 16 << 10
	HardMaxBodyBytes        = 64 << 10
	DefaultMaxResponseBytes = 4 << 10
	HardMaxResponseBytes    = 64 << 10
	DefaultMaxAttempts      = 3
	HardMaxAttempts         = 5
	DefaultTimeout          = 10 * time.Second
	HardMaxTimeout          = 30 * time.Second
	DefaultBackoff          = 200 * time.Millisecond
	HardMaxBackoff          = 5 * time.Second
	// MinSecretLen is the shortest accepted HMAC secret.
	MinSecretLen = 16

	// SignatureHeader carries "v1=<hex hmac-sha256>" over
	// "v1:<timestamp>.<body>".
	SignatureHeader = "X-Boundary-Signature"
	// TimestampHeader carries the unix time (seconds) used in the signature, so
	// receivers can reject stale deliveries.
	TimestampHeader = "X-Boundary-Timestamp"
)

// Errors. None include the URL, the secret, an address or the event content.
var (
	ErrInvalidConfig = errors.New("notify: invalid webhook configuration")
	ErrBodyTooLarge  = errors.New("notify: event body exceeds the size limit")
	ErrRedirect      = errors.New("notify: destination redirected; redirects are not followed")
	ErrRejected      = errors.New("notify: destination rejected the notification")
	ErrDelivery      = errors.New("notify: delivery failed")
)

// WebhookConfig configures a WebhookNotifier. Zero limits take the defaults.
type WebhookConfig struct {
	// URL must be https with a host, no user info and no fragment.
	URL string
	// Secret signs every delivery. At least MinSecretLen bytes. The notifier
	// keeps its own copy.
	Secret []byte
	// Timeout bounds one Notify call including all retries.
	Timeout time.Duration
	// MaxAttempts bounds the delivery attempts (first try included).
	MaxAttempts int
	// Backoff is the delay before the second attempt; it doubles afterwards.
	Backoff time.Duration
	// MaxBodyBytes caps the JSON body; MaxResponseBytes caps what is read from
	// the response.
	MaxBodyBytes     int
	MaxResponseBytes int
	// AllowedCIDRs is an explicit opt-in: addresses inside these prefixes are
	// permitted even if they are private, loopback or otherwise blocked by
	// default. Empty by default.
	AllowedCIDRs []netip.Prefix
	// Resolver resolves the destination host. Nil uses net.DefaultResolver.
	Resolver Resolver
	// Format optionally renders the request body for a validated event (for
	// example a chat-service payload). Nil keeps the default JSON encoding of
	// Event, unchanged. The output must be JSON (Content-Type is
	// application/json), is capped by MaxBodyBytes and is signed like the
	// default body. A Format error or panic fails the delivery with a fixed
	// error that carries no event text. The notify package must not import the
	// formatter packages; the caller passes the function.
	Format func(Event) ([]byte, error)
}

// String and GoString never print the URL or secret.
func (WebhookConfig) String() string   { return "notify.WebhookConfig{redacted}" }
func (WebhookConfig) GoString() string { return "notify.WebhookConfig{redacted}" }

// hooks are test-only injection points; production code leaves them zero.
type hooks struct {
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	rootCAs *x509.CertPool
	sleep   func(ctx context.Context, d time.Duration) error
	now     func() time.Time
}

// WebhookNotifier sends signed JSON events to one HTTPS endpoint.
type WebhookNotifier struct {
	url         string
	secret      []byte
	timeout     time.Duration
	maxAttempts int
	backoff     time.Duration
	maxBody     int
	maxResp     int64
	format      func(Event) ([]byte, error)
	client      *http.Client
	sleep       func(ctx context.Context, d time.Duration) error
	now         func() time.Time
}

var _ Notifier = (*WebhookNotifier)(nil)

// String never prints the URL or secret.
func (*WebhookNotifier) String() string   { return "notify.WebhookNotifier{redacted}" }
func (*WebhookNotifier) GoString() string { return "notify.WebhookNotifier{redacted}" }

// NewWebhookNotifier validates cfg and returns a notifier.
func NewWebhookNotifier(cfg WebhookConfig) (*WebhookNotifier, error) {
	return newWebhook(cfg, hooks{})
}

func newWebhook(cfg WebhookConfig, h hooks) (*WebhookNotifier, error) {
	u, err := url.Parse(cfg.URL)
	switch {
	case err != nil, u == nil:
		return nil, fmt.Errorf("%w: url", ErrInvalidConfig)
	case u.Scheme != "https":
		return nil, fmt.Errorf("%w: url must use https", ErrInvalidConfig)
	case u.Hostname() == "", u.User != nil, u.Fragment != "", u.Opaque != "":
		return nil, fmt.Errorf("%w: url", ErrInvalidConfig)
	}
	if len(cfg.Secret) < MinSecretLen {
		return nil, fmt.Errorf("%w: secret too short", ErrInvalidConfig)
	}
	pick := func(v, def, max int64, name string) (int64, error) {
		switch {
		case v < 0, v > max:
			return 0, fmt.Errorf("%w: %s", ErrInvalidConfig, name)
		case v == 0:
			return def, nil
		}
		return v, nil
	}
	timeout, err := pick(int64(cfg.Timeout), int64(DefaultTimeout), int64(HardMaxTimeout), "timeout")
	if err != nil {
		return nil, err
	}
	attempts, err := pick(int64(cfg.MaxAttempts), DefaultMaxAttempts, HardMaxAttempts, "max attempts")
	if err != nil {
		return nil, err
	}
	backoff, err := pick(int64(cfg.Backoff), int64(DefaultBackoff), int64(HardMaxBackoff), "backoff")
	if err != nil {
		return nil, err
	}
	maxBody, err := pick(int64(cfg.MaxBodyBytes), DefaultMaxBodyBytes, HardMaxBodyBytes, "max body bytes")
	if err != nil {
		return nil, err
	}
	maxResp, err := pick(int64(cfg.MaxResponseBytes), DefaultMaxResponseBytes, HardMaxResponseBytes, "max response bytes")
	if err != nil {
		return nil, err
	}
	for _, p := range cfg.AllowedCIDRs {
		if !p.IsValid() {
			return nil, fmt.Errorf("%w: allowed cidr", ErrInvalidConfig)
		}
	}

	dial := h.dial
	if dial == nil {
		res := cfg.Resolver
		if res == nil {
			res = net.DefaultResolver
		}
		sd := &netguard.Dialer{Resolver: res, Allow: append([]netip.Prefix(nil), cfg.AllowedCIDRs...), Timeout: time.Duration(timeout)}
		dial = sd.DialContext
	}
	tr := &http.Transport{
		Proxy:                  nil, // never honour proxy environment variables: they bypass the dialer checks
		DialContext:            dial,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: h.rootCAs},
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    time.Duration(timeout),
		ResponseHeaderTimeout:  time.Duration(timeout),
		MaxResponseHeaderBytes: 16 << 10,
		ForceAttemptHTTP2:      false,
	}
	w := &WebhookNotifier{
		url:         u.String(),
		secret:      append([]byte(nil), cfg.Secret...),
		timeout:     time.Duration(timeout),
		maxAttempts: int(attempts),
		backoff:     time.Duration(backoff),
		maxBody:     int(maxBody),
		maxResp:     maxResp,
		format:      cfg.Format,
		client: &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		sleep: h.sleep,
		now:   h.now,
	}
	if w.sleep == nil {
		w.sleep = sleepCtx
	}
	if w.now == nil {
		w.now = time.Now
	}
	return w, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Sign returns the signature header value for a timestamp and body.
func Sign(secret []byte, timestamp int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("v1:" + strconv.FormatInt(timestamp, 10) + "."))
	m.Write(body)
	return "v1=" + hex.EncodeToString(m.Sum(nil))
}

// Verify reports whether sig matches body and timestamp. It is for receivers
// and tests; freshness of timestamp is the receiver's responsibility.
func Verify(secret []byte, timestamp int64, body []byte, sig string) bool {
	return hmac.Equal([]byte(Sign(secret, timestamp, body)), []byte(sig))
}

// Notify delivers e. It returns an error if validation fails, the body is too
// large, the destination is not permitted, the destination rejects the event,
// or the retry budget is exhausted. It does not panic and returns no later than
// the configured timeout (or ctx cancellation).
func (w *WebhookNotifier) Notify(ctx context.Context, e Event) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrDelivery
		}
	}()
	if w == nil || w.client == nil {
		return fmt.Errorf("%w: notifier not initialised", ErrInvalidConfig)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := e.Validate(); err != nil {
		return err
	}
	e.Timestamp = e.Timestamp.UTC()
	body, merr := w.encode(e)
	if merr != nil {
		return fmt.Errorf("%w: encode", ErrInvalidEvent)
	}
	if len(body) > w.maxBody {
		return ErrBodyTooLarge
	}

	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	delay := w.backoff
	var last error
	for attempt := 1; attempt <= w.maxAttempts; attempt++ {
		retry, aerr := w.attempt(ctx, body)
		if aerr == nil {
			return nil
		}
		last = aerr
		if !retry || attempt == w.maxAttempts {
			break
		}
		if serr := w.sleep(ctx, delay); serr != nil {
			last = errTimeout
			break
		}
		if delay *= 2; delay > HardMaxBackoff {
			delay = HardMaxBackoff
		}
	}
	if errors.Is(last, ErrBlockedDestination) || errors.Is(last, ErrRedirect) || errors.Is(last, ErrRejected) {
		return last
	}
	return fmt.Errorf("%w: %s", ErrDelivery, last.Error())
}

// encode renders the body: the default JSON, or the configured formatter. A
// formatter error, panic or empty output is reported without its content.
func (w *WebhookNotifier) encode(e Event) (body []byte, err error) {
	if w.format == nil {
		return json.Marshal(e)
	}
	defer func() {
		if recover() != nil {
			body, err = nil, errTransport
		}
	}()
	body, err = w.format(e)
	if err != nil || len(body) == 0 {
		return nil, errTransport
	}
	return body, nil
}

var (
	errTimeout   = errors.New("timed out")
	errTransport = errors.New("transport error")
)

type statusError int

func (s statusError) Error() string { return "status " + strconv.Itoa(int(s)) }

// attempt makes one request. The bool reports whether a retry is sensible.
func (w *WebhookNotifier) attempt(ctx context.Context, body []byte) (bool, error) {
	ts := w.now().Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return false, errTransport
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "boundary-unlimited-notify/1")
	req.Header.Set(TimestampHeader, strconv.FormatInt(ts, 10))
	req.Header.Set(SignatureHeader, Sign(w.secret, ts, body))

	resp, err := w.client.Do(req)
	if err != nil {
		// err is a *url.Error that embeds the URL; never return it.
		switch {
		case errors.Is(err, ErrBlockedDestination):
			return false, ErrBlockedDestination
		case ctx.Err() != nil, errors.Is(err, context.DeadlineExceeded):
			return false, errTimeout
		}
		return true, errTransport
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, w.maxResp))

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		return false, nil
	case code >= 300 && code < 400:
		return false, ErrRedirect
	case code >= 400 && code < 500:
		return false, fmt.Errorf("%w: status %d", ErrRejected, code)
	case code >= 500:
		return true, statusError(code)
	}
	return false, statusError(resp.StatusCode)
}
