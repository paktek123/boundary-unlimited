// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package policyhook

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cfgSecret = "fake-secret-0123456789abcdef"

func goodCfg() EngineConfig {
	return EngineConfig{AuthorizerID: "opa", URL: "https://pdp.example.com/CANARYPATH", SecretRef: "env://PDP_SECRET", Timeout: time.Second}
}

type memEmitter struct{}

func (memEmitter) Emit(context.Context, Event) error { return nil }

func TestEngineConfigValidate(t *testing.T) {
	require.NoError(t, goodCfg().Validate())
	tests := map[string]func(*EngineConfig){
		"empty id":       func(c *EngineConfig) { c.AuthorizerID = "" },
		"bad id":         func(c *EngineConfig) { c.AuthorizerID = "Bad ID" },
		"http":           func(c *EngineConfig) { c.URL = "http://pdp.example.com/CANARYPATH" },
		"userinfo":       func(c *EngineConfig) { c.URL = "https://u:p@pdp.example.com/CANARYPATH" },
		"inline secret":  func(c *EngineConfig) { c.SecretRef = "CANARYSECRETVALUE0123456789" },
		"empty secret":   func(c *EngineConfig) { c.SecretRef = "" },
		"relative file":  func(c *EngineConfig) { c.SecretRef = "file://rel" },
		"bad env":        func(c *EngineConfig) { c.SecretRef = "env://a b" },
		"timeout high":   func(c *EngineConfig) { c.Timeout = time.Hour },
		"timeout neg":    func(c *EngineConfig) { c.Timeout = -1 },
		"cache ttl high": func(c *EngineConfig) { c.CacheTTL = time.Hour },
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			c := goodCfg()
			mut(&c)
			err := c.Validate()
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "CANARY")
		})
	}
	for _, s := range []string{fmt.Sprintf("%v", goodCfg()), fmt.Sprintf("%+v", goodCfg()), fmt.Sprintf("%#v", goodCfg())} {
		assert.NotContains(t, s, "CANARYPATH")
		assert.NotContains(t, s, "PDP_SECRET")
	}
}

func TestBuild(t *testing.T) {
	res := func(v string, err error) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(v), err }
	}
	h, err := Build(goodCfg(), BuildDeps{Emitter: memEmitter{}, Resolve: res(cfgSecret, nil)})
	require.NoError(t, err)
	assert.NotNil(t, h)

	_, err = Build(goodCfg(), BuildDeps{Resolve: res(cfgSecret, nil)})
	require.Error(t, err, "missing emitter")
	_, err = Build(goodCfg(), BuildDeps{Emitter: memEmitter{}, Resolve: res("short", nil)})
	require.Error(t, err, "short secret")
	_, err = Build(goodCfg(), BuildDeps{Emitter: memEmitter{}, Resolve: res("", ErrSecretUnavailable)})
	require.ErrorIs(t, err, ErrSecretUnavailable)
	bad := goodCfg()
	bad.URL = "http://x"
	_, err = Build(bad, BuildDeps{Emitter: memEmitter{}, Resolve: res(cfgSecret, nil)})
	require.Error(t, err)
	_ = netip.Addr{}
}

func TestResolveSecret(t *testing.T) {
	t.Setenv("BU_TEST_PDP_SECRET", cfgSecret)
	b, err := ResolveSecret("env://BU_TEST_PDP_SECRET")
	require.NoError(t, err)
	assert.Equal(t, cfgSecret, string(b))
	_, err = ResolveSecret("env://BU_TEST_PDP_UNSET")
	assert.ErrorIs(t, err, ErrSecretUnavailable)
	p := filepath.Join(t.TempDir(), "s")
	require.NoError(t, os.WriteFile(p, []byte(cfgSecret+"\n"), 0o600))
	b, err = ResolveSecret("file://" + p)
	require.NoError(t, err)
	assert.Equal(t, cfgSecret, string(b))
	big := filepath.Join(t.TempDir(), "big")
	require.NoError(t, os.WriteFile(big, make([]byte, maxSecretFileLen+1), 0o600))
	_, err = ResolveSecret("file://" + big)
	assert.ErrorIs(t, err, ErrSecretUnavailable)
	_, err = ResolveSecret("plain")
	assert.ErrorIs(t, err, ErrSecretUnavailable)
}

// The guarded transport refuses a loopback authorizer, so the hook denies
// (fail closed, reason error) without reaching it.
func TestBuild_LoopbackDenied(t *testing.T) {
	c := goodCfg()
	c.URL = "https://127.0.0.1:1/x"
	h, err := Build(c, BuildDeps{Emitter: memEmitter{}, Resolve: func(string) ([]byte, error) { return []byte(cfgSecret), nil }})
	require.NoError(t, err)
	d, r := h.Authorize(context.Background(), "req", true, Input{PrincipalID: "u_1", TargetID: "tssh_1"})
	assert.Equal(t, Deny, d)
	assert.NotEqual(t, ReasonAllow, r)
}

func TestAuditEmitter(t *testing.T) {
	c := event.TestEventerConfig(t, "TestAuditEmitter", event.TestWithAuditSink(t))
	lock := &sync.Mutex{}
	e, err := event.NewEventer(hclog.New(&hclog.LoggerOptions{Mutex: lock, Name: "test"}), lock, "TestAuditEmitter", c.EventerConfig)
	require.NoError(t, err)
	ctx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	ctx, err = event.NewRequestInfoContext(ctx, event.TestRequestInfo(t))
	require.NoError(t, err)

	require.NoError(t, AuditEmitter{}.Emit(ctx, Event{
		RequestID: "r1", PrincipalID: "u_1", TargetID: "tssh_1", AuthorizerID: "opa",
		Decision: Deny, Reason: ReasonTimeout, Latency: 5 * time.Millisecond,
	}))
	b, err := os.ReadFile(c.AllEvents.Name())
	require.NoError(t, err)
	assert.Contains(t, string(b), "authorize-session/deny/timeout")
}
