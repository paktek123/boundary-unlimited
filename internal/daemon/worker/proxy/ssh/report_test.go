// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/hostkey"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const reportTargetId = "ttcp_1234567890"

type fakeReporter struct {
	mu       sync.Mutex
	hostKey  [][2]string
	rejected [][2]string
}

func (f *fakeReporter) HostKeyFailure(_ context.Context, targetID, fp string) {
	f.mu.Lock()
	f.hostKey = append(f.hostKey, [2]string{targetID, fp})
	f.mu.Unlock()
}

func (f *fakeReporter) SessionRejected(_ context.Context, targetID, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejected = append(f.rejected, [2]string{targetID, reason})
}

func (f *fakeReporter) all() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal([]any{f.hostKey, f.rejected})
	return string(b)
}

func TestHandleSession_ReportsHostKeyFailure(t *testing.T) {
	for name, tc := range map[string]struct {
		hostKeys func(pt *passwordTarget) hostkey.Policy
	}{
		"mismatch": {func(*passwordTarget) hostkey.Policy { return pinned(newSigner(t)) }},
		"unknown key with only a CA": {func(*passwordTarget) hostkey.Policy {
			return hostkey.Policy{HostCAs: []string{string(ssh.MarshalAuthorizedKey(newSigner(t).PublicKey()))}}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			pt := newPasswordTarget(t)
			rep := &fakeReporter{}
			sentinelKey := testUpstreamPass
			client, done := startHandle(t, SessionConfig{
				Authorization: okAuth(),
				ClientHostKey: newSigner(t),
				UpstreamAddr:  pt.addr,
				Credential:    injectauth.Input{Username: testUpstreamUser, Password: sentinelKey},
				HostKeys:      tc.hostKeys(pt),
				TargetId:      reportTargetId,
				Reporter:      rep,
			})
			defer client.Close()
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("HandleSession did not return")
			}
			rep.mu.Lock()
			defer rep.mu.Unlock()

			require.Len(t, rep.hostKey, 1, "exactly one host key report")
			assert.Equal(t, reportTargetId, rep.hostKey[0][0])
			assert.Equal(t, ssh.FingerprintSHA256(pt.hostKey.PublicKey()), rep.hostKey[0][1])
			assert.Empty(t, rep.rejected)
			assert.EqualValues(t, 0, pt.authTrys.Load(), "no credential is sent to an untrusted host")

			b, _ := json.Marshal([]any{rep.hostKey, rep.rejected})
			all := string(b)
			assert.NotContains(t, all, sentinelKey)
			assert.NotContains(t, all, pt.addr)
			assert.NotContains(t, all, strings.Fields(string(ssh.MarshalAuthorizedKey(pt.hostKey.PublicKey())))[1])
		})
	}
}

func TestHandleSession_ReportsRejectedSessions(t *testing.T) {
	target := newSigner(t)
	good := func(rep Reporter) SessionConfig {
		return SessionConfig{
			Authorization: okAuth(),
			ClientHostKey: newSigner(t),
			UpstreamAddr:  "127.0.0.1:1",
			Credential:    injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
			HostKeys:      pinned(target),
			TargetId:      reportTargetId,
			Reporter:      rep,
		}
	}
	tests := []struct {
		name string
		mod  func(*SessionConfig)
		want string
	}{
		{"empty host key policy", func(c *SessionConfig) { c.HostKeys = hostkey.Policy{} }, ReasonEmptyHostKeyPolicy},
		{"unparsable host key policy", func(c *SessionConfig) { c.HostKeys = hostkey.Policy{PinnedKeys: []string{"junk"}} }, ReasonInvalidHostKeyPolicy},
		{"expired authorization", func(c *SessionConfig) { c.Authorization.Expiry = time.Now().Add(-time.Second) }, ReasonInvalidAuthorization},
		{"nil client host key", func(c *SessionConfig) { c.ClientHostKey = nil }, ReasonMissingClientHostKey},
		{"missing address", func(c *SessionConfig) { c.UpstreamAddr = "" }, ReasonMissingUpstreamAddr},
		{"no credential", func(c *SessionConfig) { c.Credential.Password = "" }, ReasonInvalidCredential},
		{"bad private key", func(c *SessionConfig) {
			c.Credential.Password = ""
			c.Credential.PrivateKey = []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nnot a key")
		}, ReasonInvalidCredential},
		{"invalid policy", func(c *SessionConfig) { c.Policy = Policy{AllowedChannelTypes: []string{"session"}} }, ReasonInvalidSessionPolicy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := &fakeReporter{}
			cfg := good(rep)
			tt.mod(&cfg)
			c1, c2 := tcpPair(t)
			defer c1.Close()
			require.Error(t, HandleSession(context.Background(), c2, cfg))
			assert.Equal(t, [][2]string{{reportTargetId, tt.want}}, rep.rejected)
			assert.Empty(t, rep.hostKey)
			all := rep.all()
			assert.NotContains(t, all, testUpstreamPass)
			assert.NotContains(t, all, "BEGIN OPENSSH")
			assert.NotContains(t, all, "127.0.0.1")
		})
	}
}

type panicReporter struct{}

func (panicReporter) HostKeyFailure(context.Context, string, string)  { panic("boom") }
func (panicReporter) SessionRejected(context.Context, string, string) { panic("boom") }

type blockingReporter struct{ release chan struct{} }

func (b blockingReporter) HostKeyFailure(context.Context, string, string)  { <-b.release }
func (b blockingReporter) SessionRejected(context.Context, string, string) { <-b.release }

func TestHandleSession_BadReporterStillRefuses(t *testing.T) {
	orig := reportTimeout
	reportTimeout = 100 * time.Millisecond
	t.Cleanup(func() { reportTimeout = orig })

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	for name, rep := range map[string]Reporter{
		"panicking": panicReporter{},
		"slow":      blockingReporter{release: release},
	} {
		t.Run(name, func(t *testing.T) {
			// A rejection before dial.
			c1, c2 := tcpPair(t)
			defer c1.Close()
			start := time.Now()
			err := HandleSession(context.Background(), c2, SessionConfig{
				Authorization: okAuth(),
				ClientHostKey: newSigner(t),
				UpstreamAddr:  "127.0.0.1:1",
				Credential:    injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
				TargetId:      reportTargetId,
				Reporter:      rep,
			})
			require.Error(t, err, "session must still be refused")
			assert.Less(t, time.Since(start), 5*time.Second)
		})
	}
}

func TestEventReporter(t *testing.T) {
	c := event.TestEventerConfig(t, "TestEventReporter", event.TestWithObservationSink(t))
	lock := &sync.Mutex{}
	logger := hclog.New(&hclog.LoggerOptions{Mutex: lock, Name: "test"})
	e, err := event.NewEventer(logger, lock, "TestEventReporter", c.EventerConfig)
	require.NoError(t, err)
	ctx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)

	r := NewEventReporter()
	r.HostKeyFailure(ctx, reportTargetId, "SHA256:abcdef")
	r.SessionRejected(ctx, reportTargetId, ReasonEmptyHostKeyPolicy)

	b, err := os.ReadFile(c.ObservationEvents.Name())
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	require.Len(t, lines, 2)
	type obs struct {
		Data map[string]any `json:"data"`
	}
	var hk, rj obs
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &hk))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &rj))
	for _, o := range []obs{hk, rj} {
		delete(o.Data, "request_info")
		delete(o.Data, "version")
	}
	assert.Equal(t, map[string]any{
		"event": "ssh_upstream_host_key_verification_failed", "target_id": reportTargetId, "host_key_fingerprint": "SHA256:abcdef",
	}, hk.Data)
	assert.Equal(t, map[string]any{
		"event": "ssh_session_rejected", "target_id": reportTargetId, "reason": ReasonEmptyHostKeyPolicy,
	}, rj.Data)
}
