// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package teams

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/notify"
)

// Sender delivers notify.Event values to a Teams webhook URL. It reuses the
// notify.WebhookNotifier transport unchanged (https only, SSRF-safe dialer,
// no redirects, no proxy, timeouts, retry budget, body and response caps) and
// only swaps the body for the Format output. The webhook URL is a secret: it
// never appears in errors, String or GoString.
type Sender struct {
	n *notify.WebhookNotifier
}

var _ notify.Notifier = (*Sender)(nil)

// NewSender validates cfg and returns a Sender. cfg.Format is always replaced
// by Format; every other field keeps its meaning and its limits.
func NewSender(cfg notify.WebhookConfig) (*Sender, error) {
	cfg.Format = Format
	n, err := notify.NewWebhookNotifier(cfg)
	if err != nil {
		return nil, err
	}
	return &Sender{n: n}, nil
}

// Notify formats and delivers ev. It returns an error carrying neither the URL
// nor event text.
func (s *Sender) Notify(ctx context.Context, ev notify.Event) error {
	if s == nil || s.n == nil {
		return fmt.Errorf("%w: sender not initialised", notify.ErrInvalidConfig)
	}
	return s.n.Notify(ctx, ev)
}

// String and GoString never print the URL.
func (*Sender) String() string   { return "teams.Sender{redacted}" }
func (*Sender) GoString() string { return "teams.Sender{redacted}" }
