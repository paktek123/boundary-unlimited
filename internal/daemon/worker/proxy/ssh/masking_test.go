// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/masking"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// canaryKey is the documented AWS example access key id.
const canaryKey = "AKIAIOSFODNN7EXAMPLE"

type fakeMaskPolicy struct {
	hash     string
	newErr   error
	failFrom int // NewRedactor calls numbered above this fail (0 = never)
	opts     []masking.Option

	mu    sync.Mutex
	calls int
}

func (p *fakeMaskPolicy) RuleSetHash() string { return p.hash }

func (p *fakeMaskPolicy) NewRedactor(w io.Writer, opt ...masking.Option) (*masking.Redactor, error) {
	p.mu.Lock()
	p.calls++
	n := p.calls
	p.mu.Unlock()
	if p.newErr != nil || (p.failFrom > 0 && n > p.failFrom) {
		return nil, errors.New("redactor unavailable")
	}
	return masking.New(w, append(append([]masking.Option{}, opt...), p.opts...)...)
}

func goodPolicy() *fakeMaskPolicy { return &fakeMaskPolicy{hash: "h1"} }

type panicDetector struct{}

func (panicDetector) Name() string               { return "boom" }
func (panicDetector) Find([]byte) []masking.Span { panic("detector exploded on " + canaryKey) }

// spyUpstream records the bytes that come out of channel Reads of the
// upstream it wraps, i.e. what a recorder installed above it would see.
type spyUpstream struct {
	inner Upstream
	mu    sync.Mutex
	seen  bytes.Buffer
}

func (s *spyUpstream) Dial(ctx context.Context) (UpstreamConn, error) {
	c, err := s.inner.Dial(ctx)
	if err != nil {
		return nil, err
	}
	return &spyConn{UpstreamConn: c, s: s}, nil
}

func (s *spyUpstream) bytes() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen.String()
}

type spyConn struct {
	UpstreamConn
	s *spyUpstream
}

func (c *spyConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	ch, reqs, err := c.UpstreamConn.OpenChannel(name, data)
	if err != nil {
		return nil, nil, err
	}
	return &spyChannel{Channel: ch, s: c.s}, reqs, nil
}

type spyChannel struct {
	ssh.Channel
	s *spyUpstream
}

func (c *spyChannel) Read(p []byte) (int, error) {
	n, err := c.Channel.Read(p)
	c.s.mu.Lock()
	c.s.seen.Write(p[:n])
	c.s.mu.Unlock()
	return n, err
}

func runEcho(t *testing.T, up Upstream, writes ...string) (string, error) {
	t.Helper()
	client, _ := startServe(t, context.Background(), okAuth(), up)
	sess, err := client.NewSession()
	require.NoError(t, err)
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	_, err = sess.SendRequest("exec", true, nil)
	require.NoError(t, err)
	for _, w := range writes {
		_, err = stdin.Write([]byte(w))
		require.NoError(t, err)
		time.Sleep(20 * time.Millisecond) // make the chunks arrive separately
	}
	require.NoError(t, stdin.Close())
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() { b, err := io.ReadAll(stdout); ch <- res{b, err} }()
	select {
	case r := <-ch:
		return string(r.b), r.err
	case <-time.After(10 * time.Second):
		t.Fatal("read did not finish")
	}
	return "", nil
}

func TestMasking_CanaryNeverReachesClientOrRecorder(t *testing.T) {
	tests := []struct {
		name   string
		writes []string
	}{
		{"single write", []string{"key=" + canaryKey + "\n"}},
		{"split across writes", []string{"key=AKIAIOSFODNN", "7EXAMPLE\n"}},
		{"split three ways", []string{"key=AKIA", "IOSFODNN7", "EXAMPLE\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &spyUpstream{inner: newMaskingUpstream(newFakeTarget(t), goodPolicy())}
			got, err := runEcho(t, spy, tt.writes...)
			require.NoError(t, err)
			assert.NotContains(t, got, canaryKey, "client must not receive the canary")
			assert.NotContains(t, spy.bytes(), canaryKey, "recorder must not receive the canary")
			assert.Contains(t, got, "key=")
			assert.Contains(t, got, "[REDACTED:")
			assert.Equal(t, got, spy.bytes(), "recorder sees exactly what the client sees")
		})
	}
}

func TestMasking_WithoutMaskingUnchanged(t *testing.T) {
	got, err := runEcho(t, newFakeTarget(t), "key="+canaryKey+"\n")
	require.NoError(t, err)
	assert.Equal(t, "key="+canaryKey+"\n", got)
}

func TestMasking_FailureDeliversNothing(t *testing.T) {
	// the detector panics on the first scan: no byte may reach the client.
	ft := newFakeTarget(t)
	p := &fakeMaskPolicy{hash: "h1", opts: []masking.Option{masking.WithDetectors(panicDetector{})}}
	got, _ := runEcho(t, newMaskingUpstream(ft, p), "key="+canaryKey+"\n")
	assert.Empty(t, got)
	select {
	case <-ft.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream connection must be closed when masking fails")
	}
}

func TestMasking_RedactorBuildFailureRejectsChannel(t *testing.T) {
	for _, from := range []int{0, 1} { // stdout redactor fails; stderr redactor fails
		ft := newFakeTarget(t)
		p := &fakeMaskPolicy{hash: "h1", failFrom: from}
		if from == 0 {
			p.newErr = errors.New("nope")
		}
		client, _ := startServe(t, context.Background(), okAuth(), newMaskingUpstream(ft, p))
		sess, err := client.NewSession()
		if err == nil {
			_, err = sess.SendRequest("exec", true, nil)
		}
		if err == nil {
			out, _ := sess.StdoutPipe()
			b, _ := io.ReadAll(out)
			assert.Empty(t, b)
		}
		select {
		case <-ft.closed:
		case <-time.After(5 * time.Second):
			t.Fatal("upstream connection must be closed")
		}
	}
}

func TestMaskReader_StderrAndErrors(t *testing.T) {
	var terminated int
	term := func() { terminated++ }

	t.Run("redacts and flushes at EOF", func(t *testing.T) {
		m, err := newMaskReader(goodPolicy(), strings.NewReader("e="+canaryKey), term)
		require.NoError(t, err)
		b, err := io.ReadAll(m)
		require.NoError(t, err)
		assert.NotContains(t, string(b), canaryKey)
		assert.Contains(t, string(b), "e=")
		assert.Zero(t, terminated)
	})
	t.Run("source error discards held bytes", func(t *testing.T) {
		boom := errors.New("link down")
		src := io.MultiReader(strings.NewReader("held "+canaryKey), errReader{boom})
		m, err := newMaskReader(goodPolicy(), src, term)
		require.NoError(t, err)
		b, err := io.ReadAll(m)
		assert.ErrorIs(t, err, boom)
		assert.Empty(t, b, "held bytes must not be flushed on error")
	})
	t.Run("discard unblocks and wipes", func(t *testing.T) {
		pr, pw := io.Pipe()
		m, err := newMaskReader(goodPolicy(), pr, term)
		require.NoError(t, err)
		done := make(chan struct{})
		go func() { _, _ = io.ReadAll(m); close(done) }()
		_, _ = pw.Write([]byte("partial"))
		time.Sleep(50 * time.Millisecond)
		m.discard()
		_ = pr.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Read did not return after discard")
		}
		_, err = m.Read(make([]byte, 8))
		assert.Error(t, err)
		m.discard() // idempotent
	})
	t.Run("invalid policy", func(t *testing.T) {
		_, err := newMaskReader(&fakeMaskPolicy{}, strings.NewReader(""), term)
		assert.Error(t, err)
		_, err = newMaskReader(nil, strings.NewReader(""), term)
		assert.Error(t, err)
		_, err = newMaskReader((*fakeMaskPolicy)(nil), strings.NewReader(""), term)
		assert.Error(t, err)
	})
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestHandleSession_Masking_RequiredWithoutPolicyRefuses(t *testing.T) {
	var typedNil *fakeMaskPolicy
	tests := []struct {
		name string
		opts []HandleOption
	}{
		{"required, no policy", []HandleOption{WithMaskingRequired()}},
		{"required, nil policy", []HandleOption{WithMasking(nil), WithMaskingRequired()}},
		{"required, typed nil policy", []HandleOption{WithMasking(typedNil), WithMaskingRequired()}},
		{"policy without hash", []HandleOption{WithMasking(&fakeMaskPolicy{})}},
		{"policy cannot build a redactor", []HandleOption{WithMasking(&fakeMaskPolicy{hash: "h", newErr: errors.New("x")})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, dials := countingListener(t)
			pt := newPasswordTarget(t)
			rep := &fakeReporter{}
			cfg := recCfg(t, pt.addr, pt.hostKey, rep)
			cfg.UpstreamAddr = addr
			c1, c2 := tcpPair(t)
			defer c1.Close()
			err := HandleSession(context.Background(), c2, cfg, tt.opts...)
			require.Error(t, err)
			assert.Zero(t, dials.Load(), "upstream must never be dialled")
			assert.Equal(t, [][2]string{{reportTargetId, ReasonMaskingUnavailable}}, rep.rejected)
			assert.NotContains(t, err.Error()+rep.all(), canaryKey)
			_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, rerr := c1.Read(make([]byte, 1))
			assert.Error(t, rerr)
		})
	}
}

func TestHandleSession_Masking_NilPolicyWithoutRequiredIsIgnored(t *testing.T) {
	pt := newPasswordTarget(t)
	cfg := recCfg(t, pt.addr, pt.hostKey, nil)
	c1, c2 := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- HandleSession(context.Background(), c2, cfg, WithMasking(nil)) }()
	client := dialClient(t, c1, cfg)
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Start("hello"))
	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleSession did not return")
	}
}

func TestHandleSession_Masking_SitsBelowRecording(t *testing.T) {
	pt := newPasswordTarget(t)
	var inner Upstream
	f := fnFactory(func(_ context.Context, _ Authorization, in Upstream) (Upstream, error) {
		inner = in
		return in, nil
	})
	cfg := recCfg(t, pt.addr, pt.hostKey, nil)
	c1, c2 := tcpPair(t)
	done := make(chan error, 1)
	go func() {
		done <- HandleSession(context.Background(), c2, cfg,
			WithMasking(goodPolicy()), WithMaskingRequired(), WithRecordingFactory(f), WithRecordingRequired())
	}()
	client := dialClient(t, c1, cfg)
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Start("hello"))
	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleSession did not return")
	}
	_, ok := inner.(*maskingUpstream)
	assert.True(t, ok, "the recording factory must wrap the masking upstream so recordings hold masked bytes only")
}

func TestMaskingPolicyInterface(t *testing.T) {
	// the production *masking.Policy satisfies MaskingPolicy.
	var _ MaskingPolicy = (*masking.Policy)(nil)
}

// stubChannel is an ssh.Channel with only Read, Stderr and Close implemented.
type stubChannel struct {
	ssh.Channel
	out, errOut io.Reader
}

func (c *stubChannel) Read(p []byte) (int, error) { return c.out.Read(p) }
func (c *stubChannel) Stderr() io.ReadWriter {
	return struct {
		io.Reader
		io.Writer
	}{c.errOut, io.Discard}
}
func (c *stubChannel) Close() error { return nil }

func TestMaskChannel_StderrIsMasked(t *testing.T) {
	conn := &maskingConn{inner: stubConn{ch: &stubChannel{
		out:    strings.NewReader("out " + canaryKey),
		errOut: strings.NewReader("err " + canaryKey),
	}}, policy: goodPolicy()}
	ch, _, err := conn.OpenChannel("session", nil)
	require.NoError(t, err)
	stdout, err := io.ReadAll(ch)
	require.NoError(t, err)
	stderr, err := io.ReadAll(ch.Stderr())
	require.NoError(t, err)
	assert.NotContains(t, string(stdout), canaryKey)
	assert.NotContains(t, string(stderr), canaryKey)
	assert.Contains(t, string(stderr), "err ")
	assert.Contains(t, string(stderr), "[REDACTED:")
}

type stubConn struct{ ch ssh.Channel }

func (c stubConn) OpenChannel(string, []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return c.ch, nil, nil
}
func (stubConn) SendRequest(string, bool, []byte) (bool, []byte, error) { return false, nil, nil }
func (stubConn) Close() error                                           { return nil }

// A channel closed while a Read is blocked in the source must not race on the
// read buffer (run with -race).
func TestMaskReader_DiscardWhileReadInFlight(t *testing.T) {
	for i := 0; i < 20; i++ {
		pr, pw := io.Pipe()
		m, err := newMaskReader(goodPolicy(), pr, func() {})
		require.NoError(t, err)
		done := make(chan struct{})
		go func() { _, _ = io.ReadAll(m); close(done) }()
		stop := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					if _, err := pw.Write([]byte("data data data")); err != nil {
						return
					}
				}
			}
		}()
		time.Sleep(5 * time.Millisecond)
		m.discard()
		close(stop)
		_ = pr.Close()
		_ = pw.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Read did not return after discard")
		}
	}
}
