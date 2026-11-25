// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/notify"
	"github.com/hashicorp/boundary/internal/notify/sender"
)

// errNotifierBuild is the only error text startup sees when the notifier
// cannot be built. The cause is reported to the system event stream by
// destination name only and never carries a URL, secret reference or secret.
var errNotifierBuild = errors.New("controller: notifier could not be built")

// buildNotifier builds the notifier fan-out from the configured destinations.
// With no destinations it returns nil, nil (no notifications; the request flow
// is unaffected). Any invalid destination, unresolvable secret or rejected
// URL fails the build (private addresses are refused at send time by the
// guarded dialer of the senders) so that startup stops instead of silently running
// without the configured notifications. The result is not yet handed to the
// access-request service: that is the registration slice (#322), and the
// config guard in internal/cmd/config stays until it lands.
func buildNotifier(ctx context.Context, dests []sender.Destination, deps sender.Deps, timeout time.Duration, resolve sender.SecretResolver) (notify.Notifier, error) {
	const op = "controller.buildNotifier"
	fo, err := sender.BuildFanOut(dests, deps, timeout, resolve)
	if err != nil {
		// Log a fixed reason with the destination count only: the wrapped
		// error names destinations but is never printed in full.
		event.WriteSysEvent(ctx, op, "notifier could not be built", "destinations", fmt.Sprint(len(dests)))
		return nil, errNotifierBuild
	}
	if fo == nil {
		return nil, nil
	}
	return fo, nil
}
