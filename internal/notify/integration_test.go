// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/accessrequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests: accessrequest.Service notifier port -> FromAccessRequest
// -> FanOut -> WebhookNotifier -> fake HTTPS server. Test code only.

const (
	itCanary = "CANARY-justification-zz91"
	itGrant  = "ids=ttcp_canary9;actions=read"
)

// itAdapter satisfies accessrequest.Notifier.
type itAdapter struct {
	n    Notifier
	mu   sync.Mutex
	errs []error
}

func (a *itAdapter) Notify(ctx context.Context, k accessrequest.NotifyKind, r accessrequest.Request) error {
	e, err := FromAccessRequest(r, Kind(k))
	if err == nil {
		err = a.n.Notify(ctx, e)
	}
	a.mu.Lock()
	a.errs = append(a.errs, err)
	a.mu.Unlock()
	return err
}

type itClock struct{}

func (itClock) Now() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) }

type delivery struct {
	body   []byte
	header http.Header
}

type itServer struct {
	*httptest.Server
	mu   sync.Mutex
	got  []delivery
	hang chan struct{}
	code int
}

func newITServer(t *testing.T, code int, hang bool) *itServer {
	t.Helper()
	s := &itServer{code: code}
	if hang {
		s.hang = make(chan struct{})
	}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.got = append(s.got, delivery{b, r.Header.Clone()})
		s.mu.Unlock()
		if s.hang != nil {
			select {
			case <-s.hang:
			case <-r.Context().Done():
			}
		}
		rw.WriteHeader(s.code)
	}))
	t.Cleanup(func() {
		if s.hang != nil {
			close(s.hang)
		}
		s.Close()
	})
	return s
}

func (s *itServer) deliveries() []delivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]delivery(nil), s.got...)
}

func newITService(t *testing.T, n accessrequest.Notifier) (*accessrequest.Service, *accessrequest.RecordingEmitter) {
	t.Helper()
	audit := &accessrequest.RecordingEmitter{}
	i := 0
	svc, err := accessrequest.NewService(accessrequest.ServiceConfig{
		Repo: accessrequest.NewMemRepository(), Policy: accessrequest.DefaultApprovalPolicy(),
		Audit: audit, Notifier: n, Clock: itClock{},
		NewId: func() (string, error) { i++; return fmt.Sprintf("ar_it%d", i), nil },
	})
	require.NoError(t, err)
	return svc, audit
}

var (
	itRequester = accessrequest.Actor{Id: "u_req"}
	itApprover  = accessrequest.Actor{Id: "u_app", CanApprove: true, Grants: []string{itGrant}}
)

// runLifecycle drives create+approve, create+deny, create+cancel (6 steps).
func runLifecycle(t *testing.T, svc *accessrequest.Service) {
	t.Helper()
	ctx := context.Background()
	mk := func() accessrequest.Request {
		r, err := svc.Create(ctx, itRequester, "o_it", []string{itGrant}, itCanary, time.Hour)
		require.NoError(t, err)
		return r
	}
	r := mk()
	_, err := svc.Approve(ctx, itApprover, r.Id)
	require.NoError(t, err)
	r = mk()
	_, err = svc.Deny(ctx, itApprover, r.Id)
	require.NoError(t, err)
	r = mk()
	_, err = svc.Cancel(ctx, itRequester, r.Id)
	require.NoError(t, err)
}

func TestIntegrationLifecycleDeliveries(t *testing.T) {
	srv := newITServer(t, http.StatusNoContent, false)
	w := newTestNotifier(t, srv.Server, nil)
	fo, err := NewFanOut(time.Second, w)
	require.NoError(t, err)
	svc, _ := newITService(t, &itAdapter{n: fo})

	runLifecycle(t, svc)

	got := srv.deliveries()
	require.Len(t, got, 6, "exactly one delivery per lifecycle step")
	wantTypes := []string{"requested", "approved", "requested", "denied", "requested", "cancelled"}
	for i, d := range got {
		ts, err := strconv.ParseInt(d.header.Get(TimestampHeader), 10, 64)
		require.NoError(t, err)
		assert.True(t, Verify([]byte(canarySecret), ts, d.body, d.header.Get(SignatureHeader)), "step %d", i)

		var m map[string]any
		require.NoError(t, json.Unmarshal(d.body, &m))
		keys := map[string]bool{}
		for k := range m {
			keys[k] = true
		}
		assert.Equal(t, map[string]bool{"type": true, "request_id": true, "scope_id": true, "timestamp": true, "summary": true}, keys)
		assert.Equal(t, "access_request."+wantTypes[i], m["type"])
		assert.Equal(t, "o_it", m["scope_id"])
		assert.Equal(t, summaries[Kind(wantTypes[i])], m["summary"])

		assert.NotContains(t, string(d.body), itCanary)
		assert.NotContains(t, string(d.body), "ttcp_canary9")
		for k, vs := range d.header {
			for _, v := range vs {
				assert.NotContains(t, v, itCanary, k)
				assert.NotContains(t, v, "ttcp_canary9", k)
				assert.NotContains(t, v, canarySecret, k)
			}
		}
	}
}

func TestIntegrationFailingAndHangingEndpointsDoNotBreakService(t *testing.T) {
	bad := newITServer(t, http.StatusInternalServerError, false)
	hang := newITServer(t, http.StatusOK, true)
	good := newITServer(t, http.StatusOK, false)
	mod := func(c *WebhookConfig) { c.MaxAttempts = 1 }
	fo, err := NewFanOut(50*time.Millisecond,
		newTestNotifier(t, bad.Server, mod),
		newTestNotifier(t, hang.Server, mod),
		newTestNotifier(t, good.Server, mod))
	require.NoError(t, err)
	ad := &itAdapter{n: fo}
	svc, audit := newITService(t, ad)

	start := time.Now()
	runLifecycle(t, svc) // every Service call must succeed (require.NoError inside)
	assert.Less(t, time.Since(start), 3*time.Second, "bounded by the fan-out timeout per step")

	assert.Len(t, good.deliveries(), 6, "healthy notifier still receives every delivery")
	assert.Len(t, bad.deliveries(), 6)
	assertAuditLifecycleAndFailures(t, audit)

	ad.mu.Lock()
	defer ad.mu.Unlock()
	require.Len(t, ad.errs, 6)
	for _, e := range ad.errs {
		require.Error(t, e)
		for _, s := range []string{e.Error(), fmt.Sprintf("%v %+v", e, e)} {
			assert.NotContains(t, s, itCanary)
			assert.NotContains(t, s, "example.com")
			assert.NotContains(t, s, canarySecret)
		}
	}
}

func TestIntegrationPrivateDestinationRefused(t *testing.T) {
	// Production dialer (no test hooks): a literal private IP is refused.
	w, err := NewWebhookNotifier(WebhookConfig{URL: "https://10.0.0.5/hook", Secret: []byte(canarySecret)})
	require.NoError(t, err)
	ad := &itAdapter{n: w}
	svc, audit := newITService(t, ad)

	runLifecycle(t, svc)

	assertAuditLifecycleAndFailures(t, audit)
	ad.mu.Lock()
	defer ad.mu.Unlock()
	require.Len(t, ad.errs, 6)
	for _, e := range ad.errs {
		assert.ErrorIs(t, e, ErrBlockedDestination)
		assert.NotContains(t, e.Error(), "10.0.0.5")
		assert.NotContains(t, e.Error(), itCanary)
	}
}

// assertAuditLifecycleAndFailures checks that the six lifecycle events are
// intact and that every failed notification was audited, with no secret.
func assertAuditLifecycleAndFailures(t *testing.T, audit *accessrequest.RecordingEmitter) {
	t.Helper()
	var lifecycle, failed int
	for _, e := range audit.Events() {
		if e.Type == accessrequest.EventNotifyFailed {
			failed++
		} else {
			lifecycle++
		}
		s := fmt.Sprintf("%+v %#v", e, e)
		assert.NotContains(t, s, canarySecret)
		assert.NotContains(t, s, itCanary)
	}
	assert.Equal(t, 6, lifecycle, "lifecycle audit unaffected by notifier failures")
	assert.Equal(t, 6, failed, "every failed notification is audited")
}
