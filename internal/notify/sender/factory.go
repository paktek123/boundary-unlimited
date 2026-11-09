// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package sender selects a notify.Notifier (generic webhook, Slack or Teams)
// from a plain typed configuration struct. It lives in a subpackage of
// internal/notify because the slack and teams packages import notify, so
// notify itself cannot import them. It is pure Go and is not wired to any
// runtime path or configuration key.
package sender

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/hashicorp/boundary/internal/notify"
	"github.com/hashicorp/boundary/internal/notify/slack"
	"github.com/hashicorp/boundary/internal/notify/teams"
)

// Supported sender types.
const (
	TypeWebhook = "webhook"
	TypeSlack   = "slack"
	TypeTeams   = "teams"
)

// SenderConfig is a plain struct, not an HCL or API field. Secret is passed as
// already-resolved bytes by the caller; this package never reads a secret
// source.
type SenderConfig struct {
	// Type is one of TypeWebhook, TypeSlack or TypeTeams. Anything else is
	// rejected.
	Type string
	// URL must be https (validated by the underlying transport).
	URL string
	// Secret is the resolved signing secret.
	Secret []byte
	// Optional limits; zero values take the notify defaults, values above the
	// hard maxima are rejected.
	Timeout     time.Duration
	MaxAttempts int
	Backoff     time.Duration
}

// String, GoString and Format never print the URL or secret, whatever verb
// is used.
func (SenderConfig) String() string   { return "sender.SenderConfig{redacted}" }
func (SenderConfig) GoString() string { return "sender.SenderConfig{redacted}" }
func (c SenderConfig) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, c.String())
}

// Deps are the shared dependencies of every sender.
type Deps struct {
	// Resolver resolves destination hosts for the guarded dialer. Nil uses
	// the system resolver.
	Resolver notify.Resolver
	// AllowedCIDRs is the explicit opt-in allowlist of the guarded dialer.
	AllowedCIDRs []netip.Prefix
}

// NewSenderFromConfig validates cfg and returns the matching Notifier. It
// fails closed: unknown types, empty URLs and non-https URLs return an error.
// Every returned Notifier uses the guarded dialer of notify.WebhookNotifier
// (SSRF block list, no redirects, no proxy); there is no way to bypass it.
func NewSenderFromConfig(cfg SenderConfig, deps Deps) (notify.Notifier, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("%w: empty url", notify.ErrInvalidConfig)
	}
	wc := notify.WebhookConfig{
		URL:          cfg.URL,
		Secret:       cfg.Secret,
		Timeout:      cfg.Timeout,
		MaxAttempts:  cfg.MaxAttempts,
		Backoff:      cfg.Backoff,
		Resolver:     deps.Resolver,
		AllowedCIDRs: deps.AllowedCIDRs,
	}
	// Each case returns an explicit untyped nil on error so the interface is
	// never a non-nil interface holding a nil pointer.
	switch cfg.Type {
	case TypeWebhook:
		n, err := notify.NewWebhookNotifier(wc)
		if err != nil {
			return nil, err
		}
		return n, nil
	case TypeSlack:
		n, err := slack.NewSender(wc)
		if err != nil {
			return nil, err
		}
		return n, nil
	case TypeTeams:
		n, err := teams.NewSender(wc)
		if err != nil {
			return nil, err
		}
		return n, nil
	default:
		return nil, fmt.Errorf("%w: unknown sender type", notify.ErrInvalidConfig)
	}
}
