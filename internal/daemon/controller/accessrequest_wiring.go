// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/accessrequest"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/kms"
)

// accessRequestSysEmitter publishes access-request audit events as controller
// system events. It forwards only the identifier, grant and timestamp fields
// of accessrequest.Event (the struct has no free-text field by design).
type accessRequestSysEmitter struct {
	write func(ctx context.Context, op event.Op, msg string, args ...any)
}

var _ accessrequest.Emitter = accessRequestSysEmitter{}

// Emit implements accessrequest.Emitter. A missing writer is an error so the
// overlay fails closed (an unauditable grant is never given).
func (e accessRequestSysEmitter) Emit(ctx context.Context, ev accessrequest.Event) error {
	if e.write == nil {
		return errors.New("controller: access request emitter has no writer")
	}
	e.write(ctx, "controller.accessRequestAudit", string(ev.Type),
		"request_id", ev.RequestId,
		"requester_id", ev.RequesterId,
		"approver_id", ev.ApproverId,
		"grants", ev.Grants,
		"at", ev.At.UTC().Format(time.RFC3339),
		"not_after", ev.NotAfter.UTC().Format(time.RFC3339),
	)
	return nil
}

// newAccessRequestOverlay builds the grant overlay provider over repo. It
// returns nil when repo is nil, which leaves the target service without an
// overlay (base grants only). It enables no request creation: that is the
// access request API.
func newAccessRequestOverlay(repo accessrequest.Repository, clock accessrequest.Clock, audit accessrequest.Emitter) targets.GrantOverlayProvider {
	if repo == nil || clock == nil || audit == nil {
		return nil
	}
	return targets.AccessRequestOverlay{
		Source: accessrequest.RepositorySource{Repo: repo},
		Clock:  clock,
		Audit:  audit,
	}
}

// buildAccessRequestOverlay builds the DB-backed provider. A repository that
// cannot be built is reported as a system event and leaves the overlay unset
// (no extra grants), never an error that blocks startup.
func buildAccessRequestOverlay(ctx context.Context, rw *db.Db, k *kms.Kms) targets.GrantOverlayProvider {
	const op = "controller.buildAccessRequestOverlay"
	repo, err := accessrequest.NewDBRepository(ctx, rw, rw, k)
	if err != nil {
		event.WriteSysEvent(ctx, op, "access request overlay not configured", "error", fmt.Sprint(errors.Is(err, accessrequest.ErrInvalidInput)))
		return nil
	}
	return newAccessRequestOverlay(repo, accessrequest.SystemClock{}, accessRequestSysEmitter{write: event.WriteSysEvent})
}
