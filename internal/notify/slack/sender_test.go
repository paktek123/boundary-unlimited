// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package slack

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/notify"
)

// fakeResolver always answers with a loopback address, which the notify
// dialer must refuse. No packet leaves the machine.
type fakeResolver struct{}

func (fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

// Fake canary values for tests only (allowed by the test-context rule).
const (
	canaryHost = "canary-host.invalid"
	canaryPath = "/services/T000/B000/CANARYSECRETPATH"
	fakeSecret = "0123456789abcdef-fake-secret"
)

func goodEvent() notify.Event {
	return notify.Event{
		Type: "access_request.created", RequestID: "arq_1234567890", ScopeID: "p_1234567890",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Summary: "request created",
	}
}

func assertNoCanary(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, c := range []string{canaryHost, "CANARYSECRETPATH", fakeSecret} {
		if strings.Contains(err.Error(), c) {
			t.Fatalf("error leaks %q: %v", c, err)
		}
	}
}

func TestNewSender_Config(t *testing.T) {
	tests := []struct {
		name string
		cfg  notify.WebhookConfig
	}{
		{"http url", notify.WebhookConfig{URL: "http://" + canaryHost + canaryPath, Secret: []byte(fakeSecret)}},
		{"user info", notify.WebhookConfig{URL: "https://u:p@" + canaryHost + canaryPath, Secret: []byte(fakeSecret)}},
		{"short secret", notify.WebhookConfig{URL: "https://" + canaryHost + canaryPath, Secret: []byte("short")}},
		{"empty", notify.WebhookConfig{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSender(tt.cfg)
			if err == nil || s != nil {
				t.Fatalf("want error, got sender=%v err=%v", s, err)
			}
			if !errors.Is(err, notify.ErrInvalidConfig) {
				t.Fatalf("want ErrInvalidConfig, got %v", err)
			}
			assertNoCanary(t, err)
		})
	}
}

func TestSender_Notify(t *testing.T) {
	cfg := notify.WebhookConfig{
		URL: "https://" + canaryHost + canaryPath, Secret: []byte(fakeSecret),
		Resolver: fakeResolver{}, MaxAttempts: 1,
		// A caller-supplied formatter must not be honoured.
		Format: func(notify.Event) ([]byte, error) { return nil, errors.New("must not run") },
	}
	s, err := NewSender(cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("blocked destination, no leak", func(t *testing.T) {
		err := s.Notify(context.Background(), goodEvent())
		if !errors.Is(err, notify.ErrBlockedDestination) {
			t.Fatalf("want ErrBlockedDestination, got %v", err)
		}
		assertNoCanary(t, err)
	})
	t.Run("invalid event rejected before any network", func(t *testing.T) {
		ev := goodEvent()
		ev.Type = "BAD TYPE"
		err := s.Notify(context.Background(), ev)
		if !errors.Is(err, notify.ErrInvalidEvent) {
			t.Fatalf("want ErrInvalidEvent, got %v", err)
		}
		assertNoCanary(t, err)
	})
	t.Run("nil sender", func(t *testing.T) {
		var n *Sender
		if err := n.Notify(context.Background(), goodEvent()); !errors.Is(err, notify.ErrInvalidConfig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("printing never shows url", func(t *testing.T) {
		for _, out := range []string{s.String(), s.GoString()} {
			if strings.Contains(out, canaryHost) || strings.Contains(out, "CANARYSECRETPATH") {
				t.Fatalf("leaks url: %s", out)
			}
		}
	})
}
