// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package accessrequests

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api"
)

// This file is adapted from api/sessions/cancel.go and so keeps its upstream
// header.

// AccessRequestUpdateResult is the result of a decision or cancel call.
type AccessRequestUpdateResult struct {
	Item     *AccessRequest
	response *api.Response
}

// GetItem returns the updated access request.
func (n AccessRequestUpdateResult) GetItem() *AccessRequest { return n.Item }

// GetResponse returns the raw API response.
func (n AccessRequestUpdateResult) GetResponse() *api.Response { return n.response }

// The create options below are for Create only; passing them to a decision call
// sends them in its body, where the server ignores or rejects them.

// WithJustification sets the free-text justification on a create request.
func WithJustification(in string) Option {
	return func(o *options) { o.postMap["justification"] = in }
}

// WithGrants sets the requested grant strings on a create request.
func WithGrants(in []string) Option {
	return func(o *options) { o.postMap["grants"] = in }
}

// WithDurationSeconds sets the requested access duration on a create request.
func WithDurationSeconds(in uint32) Option {
	return func(o *options) { o.postMap["duration_seconds"] = in }
}

// Approve approves an access request. The server refuses self-approval.
func (c *Client) Approve(ctx context.Context, id string, version uint32, opt ...Option) (*AccessRequestUpdateResult, error) {
	return c.action(ctx, "approve", id, version, opt...)
}

// Deny denies an access request.
func (c *Client) Deny(ctx context.Context, id string, version uint32, opt ...Option) (*AccessRequestUpdateResult, error) {
	return c.action(ctx, "deny", id, version, opt...)
}

// Cancel cancels the caller's own access request.
func (c *Client) Cancel(ctx context.Context, id string, version uint32, opt ...Option) (*AccessRequestUpdateResult, error) {
	return c.action(ctx, "cancel", id, version, opt...)
}

// Revoke revokes an approved access request.
func (c *Client) Revoke(ctx context.Context, id string, version uint32, opt ...Option) (*AccessRequestUpdateResult, error) {
	return c.action(ctx, "revoke", id, version, opt...)
}

func (c *Client) action(ctx context.Context, name, id string, version uint32, opt ...Option) (*AccessRequestUpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into %s request", name)
	}
	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, fmt.Errorf("zero version number passed into %s request", name)
		}
		existing, existingErr := c.Read(ctx, id, opt...)
		if existingErr != nil {
			if api.AsServerError(existingErr) != nil {
				return nil, fmt.Errorf("error from controller when performing initial check-and-set read: %w", existingErr)
			}
			return nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existing == nil || existing.Item == nil {
			return nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existing.Item.Version
	}
	opts.postMap["version"] = version

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("access-requests/%s:%s", url.PathEscape(id), name), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating %s request: %w", name, err)
	}
	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during %s call: %w", name, err)
	}

	target := new(AccessRequestUpdateResult)
	target.Item = new(AccessRequest)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding %s response: %w", name, err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}
