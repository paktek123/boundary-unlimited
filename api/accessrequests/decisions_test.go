// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package accessrequests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionsPostToColonPaths(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ar_1234567890","version":4}`))
	}))
	defer srv.Close()
	cfg, err := api.DefaultConfig()
	require.NoError(t, err)
	cfg.Addr = srv.URL
	ac, err := api.NewClient(cfg)
	require.NoError(t, err)
	c := NewClient(ac)

	for name, fn := range map[string]func(context.Context, string, uint32, ...Option) (*AccessRequestUpdateResult, error){
		"approve": c.Approve, "deny": c.Deny, "cancel": c.Cancel, "revoke": c.Revoke,
	} {
		res, err := fn(context.Background(), "ar_1234567890", 3)
		require.NoError(t, err, name)
		assert.Equal(t, "/v1/access-requests/ar_1234567890:"+name, gotPath)
		assert.EqualValues(t, 3, gotBody["version"])
		assert.Equal(t, "ar_1234567890", res.GetItem().Id)
	}

	_, err = c.Approve(context.Background(), "", 1)
	require.Error(t, err)
	_, err = c.Deny(context.Background(), "ar_1234567890", 0)
	require.Error(t, err, "zero version without automatic versioning must fail")
}

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg, err := api.DefaultConfig()
	require.NoError(t, err)
	cfg.Addr = srv.URL
	ac, err := api.NewClient(cfg)
	require.NoError(t, err)
	return NewClient(ac)
}

func TestCreatePostsOptions(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"item":{"id":"ar_1234567890"}}`))
	})
	_, err := c.Create(context.Background(), "p_1234567890",
		WithJustification("incident"), WithGrants([]string{"ids=*;type=target;actions=read"}), WithDurationSeconds(3600))
	require.NoError(t, err)
	assert.Equal(t, "/v1/access-requests", gotPath)
	assert.Equal(t, "p_1234567890", gotBody["scope_id"])
	assert.Equal(t, "incident", gotBody["justification"])
	assert.EqualValues(t, 3600, gotBody["duration_seconds"])
	assert.Equal(t, []any{"ids=*;type=target;actions=read"}, gotBody["grants"])
}

func TestAutomaticVersioningReadsThenPosts(t *testing.T) {
	var methods []string
	var postBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			postBody = map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&postBody)
		}
		_, _ = w.Write([]byte(`{"id":"ar_1234567890","version":7}`))
	})
	_, err := c.Approve(context.Background(), "ar_1234567890", 0, WithAutomaticVersioning(true))
	require.NoError(t, err)
	assert.Equal(t, []string{http.MethodGet, http.MethodPost}, methods)
	assert.EqualValues(t, 7, postBody["version"])
}

func TestServerErrorsPassThrough(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"kind":"NotFound","message":"not found"}`))
	})
	_, err := c.Approve(context.Background(), "ar_1234567890", 1)
	require.Error(t, err)
	assert.NotNil(t, api.AsServerError(err))
}
