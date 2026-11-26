// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequestscmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type seenRequest struct {
	method string
	path   string
	body   map[string]any
}

// fakeController answers every request with the given status and body and
// records what it received.
func fakeController(t *testing.T, status int, respBody string) (*httptest.Server, func() []seenRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []seenRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := seenRequest{method: r.Method, path: r.URL.Path}
		if r.Body != nil {
			m := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&m)
			s.body = m
		}
		mu.Lock()
		seen = append(seen, s)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []seenRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]seenRequest(nil), seen...)
	}
}

func runCmd(t *testing.T, fn, addr string, args ...string) (int, *cli.MockUi) {
	t.Helper()
	t.Setenv("BOUNDARY_TEST_AR_TOKEN", "at_1234567890_fakefakefake")
	ui := cli.NewMockUi()
	c := &Command{Command: base.NewCommand(ui), Func: fn}
	full := append([]string{"-addr", addr, "-token", "env://BOUNDARY_TEST_AR_TOKEN", "-keyring-type", "none"}, args...)
	return c.Run(full), ui
}

const itemJSON = `{"id":"ar_1234567890","scope_id":"p_1234567890","requester_id":"u_1234567890","state":"pending","version":4,"grants":["ids=*;type=target;actions=read"],"duration_seconds":3600}`

func TestDecisionSubcommandsSendExpectedRequest(t *testing.T) {
	for _, action := range []string{"approve", "deny", "cancel", "revoke"} {
		t.Run(action, func(t *testing.T) {
			srv, seen := fakeController(t, http.StatusOK, itemJSON)
			code, ui := runCmd(t, action, srv.URL, "-id", "ar_1234567890", "-version", "3")
			require.Equal(t, 0, code, ui.ErrorWriter.String())
			reqs := seen()
			require.Len(t, reqs, 1)
			assert.Equal(t, http.MethodPost, reqs[0].method)
			assert.Equal(t, "/v1/access-requests/ar_1234567890:"+action, reqs[0].path)
			assert.EqualValues(t, 3, reqs[0].body["version"])
			out := ui.OutputWriter.String()
			assert.Contains(t, out, "ar_1234567890")
			assert.Contains(t, out, "pending")
		})
	}
}

func TestDecisionWithoutVersionReadsFirst(t *testing.T) {
	srv, seen := fakeController(t, http.StatusOK, itemJSON)
	code, ui := runCmd(t, "approve", srv.URL, "-id", "ar_1234567890")
	require.Equal(t, 0, code, ui.ErrorWriter.String())
	reqs := seen()
	require.Len(t, reqs, 2)
	assert.Equal(t, http.MethodGet, reqs[0].method)
	assert.Equal(t, http.MethodPost, reqs[1].method)
	assert.EqualValues(t, 4, reqs[1].body["version"])
}

func TestDecisionRequiresID(t *testing.T) {
	srv, seen := fakeController(t, http.StatusOK, itemJSON)
	code, _ := runCmd(t, "approve", srv.URL)
	assert.NotEqual(t, 0, code)
	assert.Empty(t, seen())
}

func TestServerErrorsAreReported(t *testing.T) {
	srv, _ := fakeController(t, http.StatusNotFound, `{"kind":"NotFound","message":"not found"}`)
	for _, action := range []string{"approve", "deny", "cancel", "revoke", "read"} {
		args := []string{"-id", "ar_1234567890"}
		if action != "read" {
			args = append(args, "-version", "1")
		}
		code, ui := runCmd(t, action, srv.URL, args...)
		assert.NotEqual(t, 0, code, action)
		assert.Contains(t, strings.ToLower(ui.ErrorWriter.String()), "not found", action)
	}
}

func TestCreateSendsOptions(t *testing.T) {
	srv, seen := fakeController(t, http.StatusOK, itemJSON)
	code, ui := runCmd(t, "create", srv.URL, "-scope-id", "p_1234567890",
		"-justification", "incident", "-grant", "ids=*;type=target;actions=read",
		"-grant", "ids=*;type=target;actions=authorize-session", "-duration-seconds", "1h")
	require.Equal(t, 0, code, ui.ErrorWriter.String())
	reqs := seen()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodPost, reqs[0].method)
	assert.Equal(t, "/v1/access-requests", reqs[0].path)
	assert.Equal(t, "p_1234567890", reqs[0].body["scope_id"])
	assert.Equal(t, "incident", reqs[0].body["justification"])
	assert.EqualValues(t, 3600, reqs[0].body["duration_seconds"])
	assert.Len(t, reqs[0].body["grants"], 2)
}

func TestCreateRejectsBadDuration(t *testing.T) {
	srv, seen := fakeController(t, http.StatusOK, itemJSON)
	code, _ := runCmd(t, "create", srv.URL, "-scope-id", "p_1234567890", "-duration-seconds", "0")
	assert.NotEqual(t, 0, code)
	assert.Empty(t, seen())
}

func TestReadAndListPrintItems(t *testing.T) {
	srv, seen := fakeController(t, http.StatusOK, itemJSON)
	code, ui := runCmd(t, "read", srv.URL, "-id", "ar_1234567890")
	require.Equal(t, 0, code, ui.ErrorWriter.String())
	assert.Contains(t, ui.OutputWriter.String(), "ar_1234567890")
	assert.Equal(t, "/v1/access-requests/ar_1234567890", seen()[0].path)

	listSrv, listSeen := fakeController(t, http.StatusOK, `{"items":[`+itemJSON+`],"response_type":"complete"}`)
	code, ui = runCmd(t, "list", listSrv.URL, "-scope-id", "p_1234567890")
	require.Equal(t, 0, code, ui.ErrorWriter.String())
	assert.Equal(t, "/v1/access-requests", listSeen()[0].path)
	assert.Contains(t, ui.OutputWriter.String(), "ar_1234567890")
}

func TestHelpOutput(t *testing.T) {
	for _, fn := range []string{"approve", "deny", "cancel", "revoke", "create", "read", "list"} {
		c := &Command{Command: base.NewCommand(cli.NewMockUi()), Func: fn}
		h := c.Help()
		assert.Contains(t, h, "access-requests "+fn, fn)
	}
	rev := &Command{Command: base.NewCommand(cli.NewMockUi()), Func: "revoke"}
	assert.Contains(t, rev.Help(), "may be refused")
	cr := &Command{Command: base.NewCommand(cli.NewMockUi()), Func: "create"}
	h := cr.Help()
	assert.Contains(t, h, "-justification")
	assert.Contains(t, h, "-grant")
	assert.Contains(t, h, "-duration-seconds")
}
