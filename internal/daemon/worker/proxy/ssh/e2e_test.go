// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/hostkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// e2eSession runs HandleSession in-process against a fake upstream with the
// recording wrapper (over a scratch store in a temp dir) installed through
// WithRecordingFactory.
type e2eSession struct {
	h      *recHarness
	client *ssh.Client
	done   <-chan error
	rep    *fakeReporter
	pt     *ptyTarget
}

func startE2E(t *testing.T, quota, capacity int64, hk func(*ptyTarget) hostkey.Policy) *e2eSession {
	t.Helper()
	pt := newPtyTarget(t)
	h, _ := newRecHarness(t, quota, capacity, nil)
	f := fnFactory(func(ctx context.Context, _ Authorization, inner Upstream) (Upstream, error) {
		return NewRecordingUpstream(ctx, inner, h.deps)
	})
	rep := &fakeReporter{}
	cfg := recCfg(t, pt.addr, pt.hostKey, rep)
	if hk != nil {
		cfg.HostKeys = hk(pt)
	}
	c1, c2 := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- HandleSession(context.Background(), c2, cfg, WithRecordingFactory(f)) }()
	return &e2eSession{h: h, client: dialClient(t, c1, cfg), done: done, rep: rep, pt: pt}
}

func (s *e2eSession) waitDone(t *testing.T) error {
	t.Helper()
	select {
	case err := <-s.done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("HandleSession did not return")
		return nil
	}
}

func TestE2E_ShellSessionIsRecorded(t *testing.T) {
	s := startE2E(t, 1<<24, 1<<22, nil)
	sess, err := s.client.NewSession()
	require.NoError(t, err)
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	require.NoError(t, sess.Start("cat"))
	msg := "e2e-input\n"
	_, err = stdin.Write([]byte(msg))
	require.NoError(t, err)
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(stdout, buf)
	require.NoError(t, err)
	_ = stdin.Close()
	_ = sess.Close()
	_ = s.client.Close()
	require.NoError(t, s.waitDone(t))

	got := readBack(t, s.h)
	assert.Equal(t, msg, string(got.data[bsr.Inbound]))
	assert.Equal(t, msg, string(got.data[bsr.Outbound]))
	assert.EqualValues(t, 0, s.h.term.calls.Load())
	assert.EqualValues(t, 0, s.h.mark.calls.Load())
	_, err = s.h.store.Path(recSessionId)
	require.NoError(t, err, "recording must be available in the scratch store")
}

func TestE2E_ScratchQuotaExceededTerminatesSession(t *testing.T) {
	s := startE2E(t, 64<<10, 8<<10, nil)
	closeClient := func() { _ = s.client.Close() }
	s.h.term.onTerminate.Store(&closeClient)
	sess, err := s.client.NewSession()
	require.NoError(t, err)
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Start("cat"))
	chunk := make([]byte, 16<<10)
	for i := range chunk {
		chunk[i] = byte((i * 131) + ((i >> 8) * 17))
	}
	go func() {
		for i := 0; i < 64; i++ {
			if _, err := stdin.Write(chunk); err != nil {
				return
			}
		}
	}()
	_ = s.waitDone(t)
	assert.EqualValues(t, 1, s.h.term.calls.Load())
	assert.EqualValues(t, 1, s.h.mark.calls.Load())
}

func TestE2E_DisallowedChannelTypeRejected(t *testing.T) {
	s := startE2E(t, 1<<24, 1<<22, nil)
	_, _, err := s.client.OpenChannel("direct-tcpip", ssh.Marshal(struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}{"127.0.0.1", 22, "127.0.0.1", 1}))
	var oce *ssh.OpenChannelError
	require.ErrorAs(t, err, &oce)
	assert.EqualValues(t, ssh.Prohibited, oce.Reason)
	assert.EqualValues(t, 0, s.h.term.calls.Load())
}

func TestE2E_UpstreamHostKeyMismatchRefusedAndReported(t *testing.T) {
	s := startE2E(t, 1<<24, 1<<22, func(*ptyTarget) hostkey.Policy { return pinned(newSigner(t)) })
	// The client-facing handshake succeeds; the session then fails when the
	// upstream is dialled and nothing is relayed.
	if sess, err := s.client.NewSession(); err == nil {
		_ = sess.Start("cat")
	}
	_ = s.client.Close()
	require.Error(t, s.waitDone(t))
	s.rep.mu.Lock()
	defer s.rep.mu.Unlock()
	require.Len(t, s.rep.hostKey, 1, "host key failure must be reported once")
	assert.Equal(t, reportTargetId, s.rep.hostKey[0][0])
}
