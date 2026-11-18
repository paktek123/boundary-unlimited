// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package netsink builds the delivery pipeline of a network event sink from a
// validated event.SinkConfig: the secret reference is resolved, an
// httpsink.Sender is constructed (netguard egress guard, TLS 1.2 minimum, no
// redirects) and a bounded best-effort sinkqueue.Batcher sits in front of it.
//
// The builder is NOT called by the event system yet: event.SinkConfig.Validate
// still refuses http and syslog sinks as not yet supported, so no configuration
// can reach it. It exists so the final wiring slice is a small change.
//
// Both http and syslog sinks are built here. Network sinks are always
// best-effort: Write never blocks the producer, drops the oldest entries when
// the queue is full and counts every drop.
package netsink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/event/httpsink"
	"github.com/hashicorp/boundary/internal/event/sinkqueue"
	"github.com/hashicorp/boundary/internal/event/syslogfmt"
	"github.com/hashicorp/boundary/internal/event/syslogsink"
	"github.com/hashicorp/boundary/internal/netguard"
	"github.com/hashicorp/boundary/internal/notify/sender"
)

// Queue limits for network sinks. They sit below the sinkqueue hard limits.
const (
	QueueMaxEntries = 10_000
	QueueMaxBytes   = 16 << 20
	BatchSize       = 100
	FlushInterval   = 5 * time.Second
	MaxAttempts     = 3
	BaseBackoff     = time.Second
	MaxBackoff      = 30 * time.Second
)

// Errors. They never carry the url, token or entries.
var (
	ErrUnsupported = errors.New("netsink: sink type is not a network sink")
	ErrBuild       = errors.New("netsink: could not build the sink")
)

// Deps are optional test seams.
type Deps struct {
	// ResolveSecret resolves env:// and file:// references; nil uses
	// sender.DefaultSecretResolver.
	ResolveSecret sender.SecretResolver
	// Resolver and RootCAs are passed to the httpsink.Sender.
	Resolver netguard.Resolver
	RootCAs  *x509.CertPool
}

// Sink is a running network sink.
type Sink struct {
	b        *sinkqueue.Batcher
	frame    func([]byte) ([]byte, error) // nil for http
	rejected atomic.Uint64                // entries that could not be framed
}

// String never prints anything about the destination.
func (*Sink) String() string { return "netsink.Sink{redacted}" }

// Write queues one already formatted event. It never blocks and never returns
// an error to the producer: a full queue drops the oldest entry and counts it.
func (s *Sink) Write(p []byte) (int, error) {
	entry := append([]byte(nil), p...)
	if s.frame != nil {
		var err error
		if entry, err = s.frame(p); err != nil {
			s.rejected.Add(1)
			return len(p), nil
		}
	}
	if err := s.b.Enqueue(entry); err != nil {
		// Write after Close or an oversized entry: count it as dropped.
		s.rejected.Add(1)
	}
	return len(p), nil
}

// Dropped is the number of entries lost so far.
func (s *Sink) Dropped() uint64 { return s.b.Dropped() + s.rejected.Load() }

// Sent is the number of entries delivered so far.
func (s *Sink) Sent() uint64 { return s.b.Sent() }

// Close flushes what it can until ctx ends.
func (s *Sink) Close(ctx context.Context) error { return s.b.Close(ctx) }

// NewHTTP builds the pipeline for an http sink. cfg must already have passed
// cfg.Validate's network checks; this function re-validates the http block, so
// it also fails closed on an unresolvable or too short secret.
func NewHTTP(cfg *event.HTTPSinkTypeConfig, deps Deps) (*Sink, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: missing http config", ErrBuild)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%w: invalid http config", ErrBuild)
	}
	resolve := deps.ResolveSecret
	if resolve == nil {
		resolve = sender.DefaultSecretResolver
	}
	token, err := resolve(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("%w: token unavailable", ErrBuild)
	}
	prefixes, err := parseCIDRs(cfg.AllowPrivateCIDRs)
	if err != nil {
		return nil, err
	}
	hs, err := httpsink.New(httpsink.Config{
		Format:       httpsink.Format(cfg.Format),
		URL:          cfg.URL,
		Token:        token,
		RootCAs:      deps.RootCAs,
		Resolver:     deps.Resolver,
		AllowedCIDRs: prefixes,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: http transport", ErrBuild)
	}
	b, err := newQueue(hs)
	if err != nil {
		return nil, err
	}
	return &Sink{b: b}, nil
}

func newQueue(snd sinkqueue.Sender) (*sinkqueue.Batcher, error) {
	b, err := sinkqueue.New(sinkqueue.Config{
		Sender: snd, MaxEntries: QueueMaxEntries, MaxBytes: QueueMaxBytes, BatchSize: BatchSize,
		FlushInterval: FlushInterval, MaxAttempts: MaxAttempts, BaseBackoff: BaseBackoff, MaxBackoff: MaxBackoff,
		Guarantee: event.BestEffort,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: queue", ErrBuild)
	}
	return b, nil
}

// parseCIDRs parses the allow_private_cidrs list. Wildcard prefixes are
// rejected again by the transports; this only reports unparsable values.
func parseCIDRs(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, c := range in {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("%w: allow_private_cidrs", ErrBuild)
		}
		out = append(out, p)
	}
	return out, nil
}

const maxFileRefLen = 64 << 10

// readFileRef reads an absolute file:// reference, capped at maxFileRefLen.
func readFileRef(ref string) ([]byte, error) {
	f, err := os.Open(strings.TrimPrefix(ref, "file://"))
	if err != nil {
		return nil, ErrBuild
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileRefLen+1))
	if err != nil || len(b) > maxFileRefLen {
		return nil, ErrBuild
	}
	return b, nil
}

// NewSyslog builds the pipeline for a syslog sink. Each entry is wrapped in an
// RFC 5424 message (local0, info, app "boundary", msgid "event"). An entry
// that cannot be framed (for example too large for a UDP datagram) is counted
// as dropped.
func NewSyslog(cfg *event.SyslogSinkTypeConfig, deps Deps) (*Sink, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: missing syslog config", ErrBuild)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%w: invalid syslog config", ErrBuild)
	}
	network := syslogsink.Network(cfg.Network)
	if cfg.Network == "" {
		network = syslogsink.TLS
	}
	prefixes, err := parseCIDRs(cfg.AllowPrivateCIDRs)
	if err != nil {
		return nil, err
	}
	sc := syslogsink.Config{Network: network, Address: cfg.Address, Resolver: deps.Resolver, AllowedCIDRs: prefixes}
	if cfg.CAFile != "" {
		pem, err := readFileRef(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("%w: ca_file unavailable", ErrBuild)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: ca_file has no certificates", ErrBuild)
		}
		sc.RootCAs = pool
	}
	if cfg.ClientCertFile != "" {
		certPEM, err1 := readFileRef(cfg.ClientCertFile)
		keyPEM, err2 := readFileRef(cfg.ClientKeyFile)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%w: client certificate unavailable", ErrBuild)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: client certificate invalid", ErrBuild)
		}
		sc.ClientCert = &cert
	}
	if deps.RootCAs != nil {
		sc.RootCAs = deps.RootCAs
	}
	snd, err := syslogsink.New(sc)
	if err != nil {
		return nil, fmt.Errorf("%w: syslog transport", ErrBuild)
	}
	b, err := newQueue(snd)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	return &Sink{b: b, frame: func(p []byte) ([]byte, error) {
		return snd.Frame(syslogfmt.Message{
			Facility: syslogfmt.FacilityLocal0, Severity: syslogfmt.SevInfo,
			Timestamp: time.Now().UTC(), Hostname: safeHost(host),
			AppName: "boundary", MsgID: "event", Msg: string(p),
		})
	}}, nil
}

// safeHost keeps only printable ASCII and falls back to the NILVALUE.
func safeHost(h string) string {
	var out []byte
	for i := 0; i < len(h) && len(out) < syslogfmt.MaxHostnameLen; i++ {
		if h[i] > 32 && h[i] < 127 {
			out = append(out, h[i])
		}
	}
	return string(out)
}

// New builds the pipeline for sc, which must be an http or syslog sink.
func New(sc *event.SinkConfig, deps Deps) (*Sink, error) {
	if sc == nil {
		return nil, fmt.Errorf("%w: missing sink config", ErrBuild)
	}
	switch sc.Type {
	case event.HTTPSink:
		return NewHTTP(sc.HTTPConfig, deps)
	case event.SyslogSink:
		return NewSyslog(sc.SyslogConfig, deps)
	default:
		return nil, ErrUnsupported
	}
}
