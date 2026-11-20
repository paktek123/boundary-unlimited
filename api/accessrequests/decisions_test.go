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
