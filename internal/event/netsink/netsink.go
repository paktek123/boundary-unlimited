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
// Only the http sink type is built here; syslog returns ErrUnsupported. Network
// sinks are always best-effort: Write never blocks the producer, drops the
// oldest entries when the queue is full and counts every drop.
package netsink

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/event/httpsink"
	"github.com/hashicorp/boundary/internal/event/sinkqueue"
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
	ErrUnsupported = errors.New("netsink: sink type is not supported by the builder")
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
	b *sinkqueue.Batcher
}

// String never prints anything about the destination.
func (*Sink) String() string { return "netsink.Sink{redacted}" }

// Write queues one already formatted event. It never blocks and never returns
// an error to the producer: a full queue drops the oldest entry and counts it.
func (s *Sink) Write(p []byte) (int, error) {
	_ = s.b.Enqueue(append([]byte(nil), p...))
	return len(p), nil
}

// Dropped is the number of entries lost so far.
func (s *Sink) Dropped() uint64 { return s.b.Dropped() }

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
	prefixes := make([]netip.Prefix, 0, len(cfg.AllowPrivateCIDRs))
	for _, c := range cfg.AllowPrivateCIDRs {
		p, perr := netip.ParsePrefix(c)
		if perr != nil {
			return nil, fmt.Errorf("%w: allow_private_cidrs", ErrBuild)
		}
		prefixes = append(prefixes, p)
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
	b, err := sinkqueue.New(sinkqueue.Config{
		Sender: hs, MaxEntries: QueueMaxEntries, MaxBytes: QueueMaxBytes, BatchSize: BatchSize,
		FlushInterval: FlushInterval, MaxAttempts: MaxAttempts, BaseBackoff: BaseBackoff, MaxBackoff: MaxBackoff,
		Guarantee: event.BestEffort,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: queue", ErrBuild)
	}
	return &Sink{b: b}, nil
}

// New builds the pipeline for sc, which must be an http sink.
func New(sc *event.SinkConfig, deps Deps) (*Sink, error) {
	if sc == nil {
		return nil, fmt.Errorf("%w: missing sink config", ErrBuild)
	}
	switch sc.Type {
	case event.HTTPSink:
		return NewHTTP(sc.HTTPConfig, deps)
	default:
		return nil, ErrUnsupported
	}
}
