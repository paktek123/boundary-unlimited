// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package notify

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/accessrequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessRequestNotifier(t *testing.T) {
	req := accessrequest.Request{Id: "ar_1", ScopeId: "o_1", RequesterId: "u_1", Justification: "CANARY-JUSTIFICATION",
		Grants: []string{"ids=*;type=target;actions=*"}, CreatedAt: t0, DecidedAt: t1, DecidedBy: "u_2", ExpiresAt: t2}

	rec := &RecorderNotifier{}
	a, err := NewAccessRequestNotifier(rec)
	require.NoError(t, err)
	kinds := map[accessrequest.NotifyKind]string{
		accessrequest.NotifyRequested: "access_request.requested",
		accessrequest.NotifyApproved:  "access_request.approved",
		accessrequest.NotifyDenied:    "access_request.denied",
		accessrequest.NotifyCancelled: "access_request.cancelled",
		accessrequest.NotifyExpired:   "access_request.expired",
	}
	for k, typ := range kinds {
		require.NoError(t, a.Notify(context.Background(), k, req), k)
		got := rec.Events()
		assert.Equal(t, typ, got[len(got)-1].Type)
	}
	for _, e := range rec.Events() {
		s := fmt.Sprintf("%+v %#v", e, e)
		for _, leak := range []string{"CANARY", "u_1", "u_2", "target"} {
			assert.NotContains(t, s, leak)
		}
	}

	n := len(rec.Events())
	require.Error(t, a.Notify(context.Background(), accessrequest.NotifyKind("bogus"), req))
	require.Error(t, a.Notify(context.Background(), accessrequest.NotifyRequested, accessrequest.Request{}))
	assert.Len(t, rec.Events(), n, "invalid input must not be delivered")

	_, err = NewAccessRequestNotifier(nil)
	require.Error(t, err)
}

// End to end: Service -> adapter -> FanOut with failing, panicking and hanging
// destinations. Request state is unchanged and the audit log carries no secret.
func TestAccessRequestNotifier_ServiceNeverBlockedOrChanged(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	secret := "https://hooks.example.test/T/B/TOPSECRET?token=zz"
	failing := funcNotifier(func(context.Context, Event) error { return errors.New("post " + secret + ": 500") })
	panicking := funcNotifier(func(context.Context, Event) error { panic(secret) })
	hanging := funcNotifier(func(context.Context, Event) error { <-release; return nil })
	fo, err := NewFanOut(50*time.Millisecond, failing, panicking, hanging)
	require.NoError(t, err)
	ad, err := NewAccessRequestNotifier(fo)
	require.NoError(t, err)

	repo := accessrequest.NewMemRepository()
	audit := &accessrequest.RecordingEmitter{}
	n := 0
	svc, err := accessrequest.NewService(accessrequest.ServiceConfig{
		Repo: repo, Policy: accessrequest.DefaultApprovalPolicy(), Audit: audit, Notifier: ad, Clock: itClock{},
		NotifyTimeout: time.Second,
		NewId:         func() (string, error) { n++; return fmt.Sprintf("ar_%d", n), nil },
	})
	require.NoError(t, err)
	grant := "ids=ttcp_1;actions=read"
	r, err := svc.Create(context.Background(), accessrequest.Actor{Id: "u_req"}, "o_1", []string{grant}, "need access", time.Hour)
	require.NoError(t, err)
	ap, err := svc.Approve(context.Background(), accessrequest.Actor{Id: "u_app", CanApprove: true, Grants: []string{grant}}, r.Id)
	require.NoError(t, err)
	assert.Equal(t, accessrequest.StateApproved, ap.State)

	var types []accessrequest.EventType
	for _, e := range audit.Events() {
		types = append(types, e.Type)
		s := fmt.Sprintf("%+v %#v", e, e)
		assert.NotContains(t, s, "TOPSECRET")
		assert.NotContains(t, s, "token=")
	}
	assert.Equal(t, []accessrequest.EventType{
		accessrequest.EventCreate, accessrequest.EventNotifyFailed,
		accessrequest.EventApprove, accessrequest.EventNotifyFailed,
	}, types)
}
