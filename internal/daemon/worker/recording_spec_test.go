// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package worker

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	sshproxy "github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSource struct {
	meta *bsr.SessionMeta
	err  error
}

func (f fakeSource) SessionMeta(context.Context, string) (*bsr.SessionMeta, error) {
	return f.meta, f.err
}

type nopGuard struct{}

func (nopGuard) Terminate(context.Context, string) error      { return nil }
func (nopGuard) MarkIncomplete(context.Context, string) error { return nil }

func newTestProvider(t *testing.T, src AuthorisedSessionSource) *recordingSpecProvider {
	t.Helper()
	p, err := newRecordingSpecProvider(kms.TestWrapper(t), src, 1<<20, nopGuard{}, nopGuard{})
	require.NoError(t, err)
	return p
}

func auth(sid string) sshproxy.Authorization {
	return sshproxy.Authorization{SessionId: sid, ConnectionId: "sc_1234567890"}
}

func TestNewRecordingSpecProviderFailsClosed(t *testing.T) {
	w := kms.TestWrapper(t)
	src := fakeSource{}
	cases := map[string]func() (*recordingSpecProvider, error){
		"nil wrapper": func() (*recordingSpecProvider, error) {
			return newRecordingSpecProvider(nil, src, 1, nopGuard{}, nopGuard{})
		},
		"nil source": func() (*recordingSpecProvider, error) {
			return newRecordingSpecProvider(w, nil, 1, nopGuard{}, nopGuard{})
		},
		"zero capacity": func() (*recordingSpecProvider, error) {
			return newRecordingSpecProvider(w, src, 0, nopGuard{}, nopGuard{})
		},
		"nil terminator": func() (*recordingSpecProvider, error) { return newRecordingSpecProvider(w, src, 1, nil, nopGuard{}) },
		"nil marker":     func() (*recordingSpecProvider, error) { return newRecordingSpecProvider(w, src, 1, nopGuard{}, nil) },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := fn()
			require.ErrorIs(t, err, ErrRecordingSpec)
			assert.Nil(t, p)
		})
	}
}

func TestRecordingSpecBuildsFromAuthorisedSession(t *testing.T) {
	sm := bsr.TestSessionMeta("s_1234567890")
	p := newTestProvider(t, fakeSource{meta: sm})
	spec, err := p.RecordingSpec(context.Background(), auth("s_1234567890"))
	require.NoError(t, err)
	assert.Equal(t, "s_1234567890", spec.Meta.Id)
	assert.Equal(t, sm, spec.SessionMeta)
	assert.Equal(t, "sc_1234567890", spec.ConnectionId)
	assert.Equal(t, int64(1<<20), spec.Capacity)
	require.NotNil(t, spec.Keys)
	assert.NotNil(t, spec.Terminator)
	assert.NotNil(t, spec.Marker)
}

func TestRecordingSpecDistinctKeysPerSession(t *testing.T) {
	p := newTestProvider(t, fakeSource{meta: bsr.TestSessionMeta("s_1234567890")})
	a, err := p.RecordingSpec(context.Background(), auth("s_1234567890"))
	require.NoError(t, err)
	b, err := p.RecordingSpec(context.Background(), auth("s_1234567890"))
	require.NoError(t, err)
	assert.NotEqual(t, a.Keys.WrappedBsrKey.WrappedKey, b.Keys.WrappedBsrKey.WrappedKey)
	assert.NotEqual(t, a.Keys.BsrKey.Key, b.Keys.BsrKey.Key)
}

func TestRecordingSpecRefusals(t *testing.T) {
	good := bsr.TestSessionMeta("s_1234567890")
	cases := map[string]struct {
		src fakeSource
		a   sshproxy.Authorization
	}{
		"source error":       {fakeSource{err: errors.New("boom canary-token")}, auth("s_1234567890")},
		"nil meta":           {fakeSource{}, auth("s_1234567890")},
		"session mismatch":   {fakeSource{meta: good}, auth("s_other00000")},
		"missing session":    {fakeSource{meta: good}, sshproxy.Authorization{ConnectionId: "sc_1"}},
		"missing connection": {fakeSource{meta: good}, sshproxy.Authorization{SessionId: "s_1234567890"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := newTestProvider(t, tc.src)
			spec, err := p.RecordingSpec(context.Background(), tc.a)
			require.ErrorIs(t, err, ErrRecordingSpec)
			assert.Nil(t, spec.Keys)
			assert.NotContains(t, err.Error(), "canary-token")
		})
	}
}

func TestRecordingSpecKeyCreationFailureRefuses(t *testing.T) {
	mw := &kms.MockWrapper{Wrapper: kms.TestWrapper(t), WithEncryptErrorOn: 1, EncryptErr: fmt.Errorf("canary-key-bytes")}
	p, err := newRecordingSpecProvider(mw, fakeSource{meta: bsr.TestSessionMeta("s_1234567890")}, 1, nopGuard{}, nopGuard{})
	require.NoError(t, err)
	spec, err := p.RecordingSpec(context.Background(), auth("s_1234567890"))
	require.ErrorIs(t, err, ErrRecordingSpec)
	assert.Nil(t, spec.Keys)
	assert.NotContains(t, err.Error(), "canary-key-bytes")
}

func TestRecordingSpecKeysAreRedactedWhenPrinted(t *testing.T) {
	p := newTestProvider(t, fakeSource{meta: bsr.TestSessionMeta("s_1234567890")})
	spec, err := p.RecordingSpec(context.Background(), auth("s_1234567890"))
	require.NoError(t, err)
	for _, f := range []string{"%v", "%+v", "%s", "%#v"} {
		out := fmt.Sprintf(f, spec.Keys)
		assert.NotContains(t, out, string(spec.Keys.BsrKey.Key))
		assert.NotContains(t, out, string(spec.Keys.PrivKey.Key))
	}
}
