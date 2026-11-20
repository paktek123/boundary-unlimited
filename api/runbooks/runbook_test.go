// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbooks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadAndDeletePaths(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(`{"id":"rb_1234567890","commit_sha":"","script_path":"a.sh","version":2}`))
	}))
	defer srv.Close()
	cfg, err := api.DefaultConfig()
	require.NoError(t, err)
	cfg.Addr = srv.URL
	ac, err := api.NewClient(cfg)
	require.NoError(t, err)
	c := NewClient(ac)

	res, err := c.Read(context.Background(), "rb_1234567890")
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, gotMethod)
	assert.Equal(t, "/v1/runbooks/rb_1234567890", gotPath)
	assert.Equal(t, "a.sh", res.GetItem().ScriptPath)

	_, err = c.Delete(context.Background(), "rb_1234567890")
	require.NoError(t, err)
	assert.Equal(t, http.MethodDelete, gotMethod)
	assert.Equal(t, "/v1/runbooks/rb_1234567890", gotPath)

	_, err = c.Read(context.Background(), "")
	require.Error(t, err)
}

func TestServerErrorsPassThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"kind":"NotFound","message":"not found"}`))
	}))
	defer srv.Close()
	cfg, err := api.DefaultConfig()
	require.NoError(t, err)
	cfg.Addr = srv.URL
	ac, err := api.NewClient(cfg)
	require.NoError(t, err)
	c := NewClient(ac)

	_, err = c.Read(context.Background(), "rb_1234567890")
	require.Error(t, err)
	assert.NotNil(t, api.AsServerError(err))
	_, err = c.Delete(context.Background(), "rb_1234567890")
	require.Error(t, err)
	assert.NotNil(t, api.AsServerError(err))
}
