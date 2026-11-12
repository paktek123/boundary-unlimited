// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package sender

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/notify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	canarySecret = "CANARY-secret-value-0123456789"
	canaryHost   = "hooks.example.com/CANARYPATH"
)

type fixedResolver struct{ addr string }

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr(r.addr)}, nil
}

func dest(secretRef string) Destination {
	return Destination{Name: "ops", Type: TypeWebhook, URL: "https://" + canaryHost, SecretRef: secretRef}
}

func staticResolver(v string, err error) SecretResolver {
	return func(string) ([]byte, error) { return []byte(v), err }
}

func TestBuildFanOut(t *testing.T) {
	f, err := BuildFanOut(nil, Deps{}, 0, nil)
	require.NoError(t, err)
	assert.Nil(t, f, "no destinations -> no fan-out")

	f, err = BuildFanOut([]Destination{dest("env://S")}, Deps{}, time.Second, staticResolver(canarySecret, nil))
	require.NoError(t, err)
	assert.NotNil(t, f)

	tests := map[string]struct {
		dests []Destination
		res   SecretResolver
	}{
		"short secret":  {[]Destination{dest("env://S")}, staticResolver("short", nil)},
		"unresolvable":  {[]Destination{dest("env://S")}, staticResolver("", ErrSecretUnavailable)},
		"inline secret": {[]Destination{dest(canarySecret)}, staticResolver(canarySecret, nil)},
		"duplicate":     {[]Destination{dest("env://S"), dest("env://S")}, staticResolver(canarySecret, nil)},
		"unknown type":  {[]Destination{{Name: "a", Type: "x", URL: "https://" + canaryHost, SecretRef: "env://S"}}, staticResolver(canarySecret, nil)},
		"http":          {[]Destination{{Name: "a", Type: TypeSlack, URL: "http://" + canaryHost, SecretRef: "env://S"}}, staticResolver(canarySecret, nil)},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := BuildFanOut(tc.dests, Deps{}, 0, tc.res)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "CANARY")
		})
	}
}

func TestDestinationRedaction(t *testing.T) {
	d := dest("env://SECRET_NAME")
	for _, s := range []string{fmt.Sprintf("%v", d), fmt.Sprintf("%+v", d), fmt.Sprintf("%#v", d), d.String()} {
		assert.NotContains(t, s, "CANARY")
		assert.NotContains(t, s, "SECRET_NAME")
	}
}

func TestDefaultSecretResolver(t *testing.T) {
	t.Setenv("BU_TEST_NOTIFY_SECRET", canarySecret)
	b, err := DefaultSecretResolver("env://BU_TEST_NOTIFY_SECRET")
	require.NoError(t, err)
	assert.Equal(t, canarySecret, string(b))

	_, err = DefaultSecretResolver("env://BU_TEST_NOTIFY_UNSET")
	assert.ErrorIs(t, err, ErrSecretUnavailable)

	p := filepath.Join(t.TempDir(), "s")
	require.NoError(t, os.WriteFile(p, []byte(canarySecret+"\n"), 0o600))
	b, err = DefaultSecretResolver("file://" + p)
	require.NoError(t, err)
	assert.Equal(t, canarySecret, string(b))

	big := filepath.Join(t.TempDir(), "big")
	require.NoError(t, os.WriteFile(big, make([]byte, maxSecretFileLen+1), 0o600))
	_, err = DefaultSecretResolver("file://" + big)
	assert.ErrorIs(t, err, ErrSecretUnavailable)
	_, err = DefaultSecretResolver("file:///nonexistent/x")
	assert.ErrorIs(t, err, ErrSecretUnavailable)
	_, err = DefaultSecretResolver("plain")
	assert.ErrorIs(t, err, ErrSecretUnavailable)
}

// A destination that resolves to a blocked address is refused at dial time.
func TestBuildFanOut_BlockedAddressRefusedAtDial(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1"} {
		t.Run(addr, func(t *testing.T) {
			d := dest("env://S")
			d.Type = TypeSlack
			f, err := BuildFanOut([]Destination{d}, Deps{Resolver: fixedResolver{addr}}, time.Second, staticResolver(canarySecret, nil))
			require.NoError(t, err)
			err = f.Notify(context.Background(), notify.Event{Type: "access_request.created", RequestID: "ar_1", ScopeID: "p_1", Timestamp: time.Now(), Summary: "x"})
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "CANARY")
		})
	}
}
