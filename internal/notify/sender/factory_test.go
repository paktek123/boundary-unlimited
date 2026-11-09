// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package sender

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/notify"
)

const (
	fakeSecret = "0123456789abcdef-fake-secret"
	fakeURL    = "https://canary-host.invalid/services/CANARYPATH"
)

type countingResolver struct{ calls atomic.Int32 }

func (r *countingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls.Add(1)
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func TestNewSenderFromConfig_Rejects(t *testing.T) {
	tests := []struct {
		name string
		cfg  SenderConfig
	}{
		{"unknown type", SenderConfig{Type: "pagerduty", URL: fakeURL, Secret: []byte(fakeSecret)}},
		{"empty type", SenderConfig{URL: fakeURL, Secret: []byte(fakeSecret)}},
		{"empty url", SenderConfig{Type: TypeSlack, Secret: []byte(fakeSecret)}},
		{"http url", SenderConfig{Type: TypeTeams, URL: "http://canary-host.invalid/x", Secret: []byte(fakeSecret)}},
		{"short secret", SenderConfig{Type: TypeWebhook, URL: fakeURL, Secret: []byte("x")}},
		{"over hard max", SenderConfig{Type: TypeWebhook, URL: fakeURL, Secret: []byte(fakeSecret), MaxAttempts: 99}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := NewSenderFromConfig(tt.cfg, Deps{})
			if err == nil || n != nil {
				t.Fatalf("want error and nil notifier, got %v, %v", n, err)
			}
			for _, c := range []string{"canary-host", "CANARYPATH", fakeSecret} {
				if strings.Contains(err.Error(), c) {
					t.Fatalf("error leaks %q", c)
				}
			}
		})
	}
}

func TestNewSenderFromConfig_UsesGuardedDialer(t *testing.T) {
	ev := notify.Event{
		Type: "access_request.created", RequestID: "arq_1234567890", ScopeID: "p_1234567890",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Summary: "request created",
	}
	for _, typ := range []string{TypeWebhook, TypeSlack, TypeTeams} {
		t.Run(typ, func(t *testing.T) {
			res := &countingResolver{}
			n, err := NewSenderFromConfig(SenderConfig{Type: typ, URL: fakeURL, Secret: []byte(fakeSecret), MaxAttempts: 1}, Deps{Resolver: res})
			if err != nil {
				t.Fatal(err)
			}
			err = n.Notify(context.Background(), ev)
			if err == nil {
				t.Fatal("loopback destination must be refused")
			}
			if res.calls.Load() == 0 {
				t.Fatal("fake resolver was not consulted: guarded dialer not used")
			}
			if !errors.Is(err, notify.ErrDelivery) && !errors.Is(err, notify.ErrBlockedDestination) {
				t.Logf("error: %v", err)
			}
			if strings.Contains(err.Error(), "canary-host") || strings.Contains(err.Error(), "CANARYPATH") {
				t.Fatal("error leaks destination")
			}
		})
	}
}

func TestSenderConfig_NeverPrintsSecrets(t *testing.T) {
	cfg := SenderConfig{Type: TypeSlack, URL: fakeURL, Secret: []byte(fakeSecret)}
	for _, out := range []string{
		fmt.Sprint(cfg), fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg),
		fmt.Sprintf("%s", cfg), fmt.Sprintf("%v", &cfg), fmt.Sprintf("%+v", &cfg), cfg.String(), cfg.GoString(),
	} {
		for _, c := range []string{"CANARYPATH", "canary-host", fakeSecret} {
			if strings.Contains(out, c) {
				t.Fatalf("output %q leaks %q", out, c)
			}
		}
	}
}
