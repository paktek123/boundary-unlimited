// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package controller

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/policyhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildPolicyAuthorizer(t *testing.T) {
	authz, err := buildPolicyAuthorizer(nil, policyhook.BuildDeps{})
	require.NoError(t, err)
	assert.Nil(t, authz, "stanza absent: no authorizer")

	cfg := &policyhook.EngineConfig{AuthorizerID: "opa", URL: "https://pdp.example.com/x", SecretRef: "env://BU_TEST_PDP_UNSET_SECRET", Timeout: time.Second}
	_, err = buildPolicyAuthorizer(cfg, policyhook.BuildDeps{Emitter: policyhook.AuditEmitter{}})
	require.Error(t, err, "stanza present + unresolvable secret must stop startup")
	assert.NotContains(t, err.Error(), "pdp.example.com")
	assert.NotContains(t, err.Error(), "BU_TEST_PDP_UNSET_SECRET")

	t.Setenv("BU_TEST_PDP_SECRET", "fake-secret-0123456789abcdef")
	cfg.SecretRef = "env://BU_TEST_PDP_SECRET"
	authz, err = buildPolicyAuthorizer(cfg, policyhook.BuildDeps{Emitter: policyhook.AuditEmitter{}})
	require.NoError(t, err)
	assert.NotNil(t, authz)
}
