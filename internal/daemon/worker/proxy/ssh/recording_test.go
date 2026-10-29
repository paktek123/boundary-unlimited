// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	bssh "github.com/hashicorp/boundary/internal/bsr/ssh"
	"github.com/hashicorp/boundary/internal/bsr/ssh/recorder"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	recSessionId   = "s_1234567890"
	recRecordingId = "sr_1234567890"
	recConnId      = "cr_1234567890"
	recChanId      = "chr_1234567890"
)

// memFS is a minimal storage.FS. Every file write is also passed to onWrite,
// which stands in for the scratch store.
type memFS struct {
	mu      sync.Mutex
	roots   map[string]*memContainer
	onWrite func(p []byte) error
}

type memContainer struct {
	fs    *memFS
	files map[string]*memFile
	subs  map[string]*memContainer
}

type memFile struct {
	c    *memContainer
	data []byte
	r    *bytes.Reader
	w    bool
	done bool
	name string
}

func newMemFS(onWrite func([]byte) error) *memFS {
	return &memFS{roots: map[string]*memContainer{}, onWrite: onWrite}
}

func (f *memFS) newContainer() *memContainer {
	return &memContainer{fs: f, files: map[string]*memFile{}, subs: map[string]*memContainer{}}
}

func (f *memFS) New(_ context.Context, name string) (storage.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.roots[name]; ok {
		return nil, iofs.ErrExist
	}
	c := f.newContainer()
	f.roots[name] = c
	return c, nil
}

func (f *memFS) Open(_ context.Context, name string) (storage.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.roots[name]
	if !ok {
		return nil, iofs.ErrNotExist
	}
	return c, nil
}

func (c *memContainer) Close() error { return nil }

func (c *memContainer) Create(_ context.Context, name string) (storage.File, error) {
	c.fs.mu.Lock()
	defer c.fs.mu.Unlock()
	f := &memFile{c: c, w: true, name: name}
	c.files[name] = f
	return f, nil
}

func (c *memContainer) OpenFile(_ context.Context, name string, opt ...storage.Option) (storage.File, error) {
	o := storage.GetOpts(opt...)
	if o.WithCreateFile {
		return c.Create(context.Background(), name)
	}
	c.fs.mu.Lock()
	defer c.fs.mu.Unlock()
	src, ok := c.files[name]
	if !ok {
		return nil, iofs.ErrNotExist
	}
	return &memFile{c: c, name: name, data: src.data, r: bytes.NewReader(src.data)}, nil
}

func (c *memContainer) SubContainer(_ context.Context, name string, opt ...storage.Option) (storage.Container, error) {
	o := storage.GetOpts(opt...)
	c.fs.mu.Lock()
	defer c.fs.mu.Unlock()
	if sc, ok := c.subs[name]; ok {
		return sc, nil
	}
	if !o.WithCreateFile {
		return nil, iofs.ErrNotExist
	}
	sc := c.fs.newContainer()
	c.subs[name] = sc
	return sc, nil
}

func (f *memFile) Write(p []byte) (int, error) {
	if !f.w {
		return 0, errors.New("read-only file")
	}
	if hook := f.c.fs.onWrite; hook != nil {
		if err := hook(p); err != nil {
			return 0, err
		}
	}
	f.c.fs.mu.Lock()
	defer f.c.fs.mu.Unlock()
	f.data = append(f.data, p...)
	return len(p), nil
}

func (f *memFile) WriteString(s string) (int, error) { return f.Write([]byte(s)) }

func (f *memFile) WriteAndClose(p []byte) (int, error) {
	n, err := f.Write(p)
	if err != nil {
		return n, err
	}
	return n, f.Close()
}

func (f *memFile) Read(p []byte) (int, error) {
	if f.r == nil {
		return 0, errors.New("write-only file")
	}
	return f.r.Read(p)
}

func (f *memFile) Close() error {
	f.c.fs.mu.Lock()
	defer f.c.fs.mu.Unlock()
	if f.done {
		return errors.New("close on closed file")
	}
	f.done = true
	return nil
}

type memInfo struct {
	name string
	size int64
}

func (i memInfo) Name() string        { return i.name }
func (i memInfo) Size() int64         { return i.size }
func (i memInfo) Mode() iofs.FileMode { return 0o644 }
func (i memInfo) ModTime() time.Time  { return time.Time{} }
func (i memInfo) IsDir() bool         { return false }
func (i memInfo) Sys() any            { return nil }
func (f *memFile) Stat() (iofs.FileInfo, error) {
	f.c.fs.mu.Lock()
	defer f.c.fs.mu.Unlock()
	return memInfo{name: f.name, size: int64(len(f.data))}, nil
}

type fakeTerminator struct {
	calls atomic.Int32
	// onTerminate stands in for what the real terminator does to the client.
	onTerminate atomic.Pointer[func()]
}

func (f *fakeTerminator) Terminate(context.Context, string) error {
	f.calls.Add(1)
	if fn := f.onTerminate.Load(); fn != nil {
		(*fn)()
	}
	return nil
}

type fakeMarker struct {
	calls atomic.Int32
}

func (f *fakeMarker) MarkIncomplete(context.Context, string) error { f.calls.Add(1); return nil }

type recHarness struct {
	fs    *memFS
	store *scratch.Store
	sess  *bsr.Session
	keyFn kms.KeyUnwrapCallbackFunc
	rec   *recorder.Recorder
	term  *fakeTerminator
	mark  *fakeMarker
	deps  RecordingDeps
}

// countingUpstream counts Dial calls on an Upstream.
type countingUpstream struct {
	Upstream
	dials atomic.Int32
}

func (c *countingUpstream) Dial(ctx context.Context) (UpstreamConn, error) {
	c.dials.Add(1)
	return c.Upstream.Dial(ctx)
}

func newRecHarness(t *testing.T, quota, capacity int64, inner Upstream) (*recHarness, *countingUpstream) {
	t.Helper()
	ctx := context.Background()
	store, err := scratch.New(t.TempDir(), quota)
	require.NoError(t, err)
	// The reservation is made by RecordingUpstream.Dial, so the BSR session
	// (whose creation writes meta files) is built against a hook that only
	// reaches the store once the reservation exists.
	var reserved atomic.Bool
	fs := newMemFS(func(p []byte) error {
		if !reserved.Load() {
			return nil
		}
		_, err := store.Write(recSessionId, p)
		return err
	})
	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), recSessionId)
	require.NoError(t, err)
	keyFn := func(kms.WrappedKeys) (kms.UnwrappedKeys, error) {
		return kms.UnwrappedKeys{BsrKey: keys.BsrKey, PrivKey: keys.PrivKey}, nil
	}
	sess, err := bsr.NewSession(ctx, &bsr.SessionRecordingMeta{Id: recRecordingId, Protocol: bssh.Protocol},
		bsr.TestSessionMeta(recSessionId), fs, keys, bsr.WithSupportsMultiplex(true))
	require.NoError(t, err)
	rec, err := recorder.NewRecorder(ctx, sess, recConnId)
	require.NoError(t, err)

	cu := &countingUpstream{Upstream: inner}
	h := &recHarness{fs: fs, store: store, sess: sess, keyFn: keyFn, rec: rec, term: &fakeTerminator{}, mark: &fakeMarker{}}
	h.deps = RecordingDeps{SessionId: recSessionId, Capacity: capacity, Scratch: &reserveFlag{Store: store, flag: &reserved}, Recorder: rec, Terminator: h.term, Marker: h.mark,
		NewChannelId: func() (string, error) { return recChanId, nil }}
	return h, cu
}

// reserveFlag flips a flag once the reservation succeeded.
type reserveFlag struct {
	*scratch.Store
	flag *atomic.Bool
}

func (r *reserveFlag) Reserve(id string, c int64) error {
	if err := r.Store.Reserve(id, c); err != nil {
		return err
	}
	r.flag.Store(true)
	return nil
}

func TestRecordingUpstream_InvalidArgs(t *testing.T) {
	ctx := context.Background()
	h, cu := newRecHarness(t, 1<<20, 1<<10, newFakeTarget(t))
	_, err := NewRecordingUpstream(ctx, nil, h.deps)
	require.Error(t, err)
	for name, mod := range map[string]func(*RecordingDeps){
		"session id": func(d *RecordingDeps) { d.SessionId = "" },
		"scratch":    func(d *RecordingDeps) { d.Scratch = nil },
		"recorder":   func(d *RecordingDeps) { d.Recorder = nil },
		"terminator": func(d *RecordingDeps) { d.Terminator = nil },
		"marker":     func(d *RecordingDeps) { d.Marker = nil },
		"capacity":   func(d *RecordingDeps) { d.Capacity = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			d := h.deps
			mod(&d)
			_, err := NewRecordingUpstream(ctx, cu, d)
			require.Error(t, err)
		})
	}
}

func TestRecordingUpstream_NoCapacityFailsBeforeInnerDial(t *testing.T) {
	h, cu := newRecHarness(t, 10, 1<<20, newFakeTarget(t))
	ru, err := NewRecordingUpstream(context.Background(), cu, h.deps)
	require.NoError(t, err)
	conn, err := ru.Dial(context.Background())
	require.ErrorIs(t, err, scratch.ErrQuotaExceeded)
	assert.Nil(t, conn)
	assert.EqualValues(t, 0, cu.dials.Load(), "inner upstream must not be dialled")
}

func TestRecordingUpstream_InnerDialFailureReleasesReservation(t *testing.T) {
	ft := newFakeTarget(t)
	ft.failDial = true
	h, cu := newRecHarness(t, 1<<20, 1<<10, ft)
	ru, err := NewRecordingUpstream(context.Background(), cu, h.deps)
	require.NoError(t, err)
	_, err = ru.Dial(context.Background())
	require.Error(t, err)
	assert.EqualValues(t, 1, cu.dials.Load())
	assert.EqualValues(t, 0, h.store.Used())
}

// ptyTarget is an in-process SSH server that requires the test password,
// accepts pty-req, exec and window-change, echoes session data and sends an
// exit-status request once the client closes its input.
type ptyTarget struct {
	addr    string
	hostKey ssh.Signer
}

func newPtyTarget(t *testing.T) *ptyTarget {
	t.Helper()
	pt := &ptyTarget{hostKey: newSigner(t)}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == testUpstreamUser && string(pw) == testUpstreamPass {
				return nil, nil
			}
			return nil, assert.AnError
		},
	}
	cfg.AddHostKey(pt.hostKey)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	pt.addr = l.Addr().String()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range creqs {
							if r.WantReply {
								_ = r.Reply(r.Type == "pty-req" || r.Type == "exec" || r.Type == "window-change", nil)
							}
						}
					}()
					go func() {
						_, _ = io.Copy(ch, ch)
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						_ = ch.Close()
						_ = sc.Close()
					}()
				}
			}()
		}
	}()
	return pt
}

type scanned struct {
	reqTypes map[bsr.Direction][]string
	data     map[bsr.Direction][]byte
}

// readBack finalises the BSR, validates it and returns what was recorded for
// the only channel of the connection.
func readBack(t *testing.T, h *recHarness) scanned {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, h.sess.EncodeSummary(ctx, &bsr.BaseSessionSummary{Id: recRecordingId, ConnectionCount: 1}))
	require.NoError(t, h.sess.Close(ctx))
	v, err := bsr.Validate(ctx, recRecordingId, h.fs, h.keyFn)
	require.NoError(t, err)
	require.True(t, v.Valid, "BSR must validate: %+v", v)

	opened, err := bsr.OpenSession(ctx, recRecordingId, h.fs, h.keyFn)
	require.NoError(t, err)
	defer opened.Close(ctx)
	conn, err := opened.OpenConnection(ctx, recConnId)
	require.NoError(t, err)
	defer conn.Close(ctx)
	require.EqualValues(t, 1, conn.Summary.(*bsr.BaseConnectionSummary).ChannelCount)
	oc, err := conn.OpenChannel(ctx, recChanId)
	require.NoError(t, err)
	defer oc.Close(ctx)

	out := scanned{reqTypes: map[bsr.Direction][]string{}, data: map[bsr.Direction][]byte{}}
	for _, d := range []bsr.Direction{bsr.Inbound, bsr.Outbound} {
		rs, err := oc.OpenRequestScanner(ctx, d)
		require.NoError(t, err)
		for {
			c, err := rs.Scan(ctx)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			out.reqTypes[d] = append(out.reqTypes[d], string(c.GetType()))
		}
		rs.Close()
		ms, err := oc.OpenMessageScanner(ctx, d)
		require.NoError(t, err)
		for {
			c, err := ms.Scan(ctx)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			if dc, ok := c.(*bssh.DataChunk); ok {
				out.data[d] = append(out.data[d], dc.Data...)
			}
		}
		ms.Close()
	}
	return out
}

func TestRecordingUpstream_RecordsSessionAndReadsBack(t *testing.T) {
	pt := newPtyTarget(t)
	inner, err := NewClientUpstream(context.Background(), pt.addr,
		injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
		ssh.FixedHostKey(pt.hostKey.PublicKey()))
	require.NoError(t, err)
	h, cu := newRecHarness(t, 1<<24, 1<<22, inner)
	cu.Upstream = inner
	ru, err := NewRecordingUpstream(context.Background(), cu, h.deps)
	require.NoError(t, err)

	client, done := startServe(t, context.Background(), okAuth(), ru)
	sess, err := client.NewSession()
	require.NoError(t, err)
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	require.NoError(t, sess.Start("cat"))
	_, err = stdin.Write([]byte("ping-from-client\n"))
	require.NoError(t, err)
	buf := make([]byte, len("ping-from-client\n"))
	_, err = io.ReadFull(stdout, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping-from-client\n", string(buf))
	// Ask for a reply so the request is known to have been delivered, and so
	// recorded, before the session is torn down.
	ok, err := sess.SendRequest("window-change", true, ssh.Marshal(struct{ Cols, Rows, Width, Height uint32 }{100, 40, 0, 0}))
	require.NoError(t, err)
	require.True(t, ok)
	_ = stdin.Close()
	_ = sess.Close()
	_ = client.Close()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}

	got := readBack(t, h)
	assert.Equal(t, "ping-from-client\n", string(got.data[bsr.Inbound]))
	assert.Equal(t, "ping-from-client\n", string(got.data[bsr.Outbound]))
	assert.Equal(t, []string{"HEAD", "PTYR", "EXEC", "WCHG", "DONE"}, got.reqTypes[bsr.Inbound], "head chunk first, then requests in order")
	assert.EqualValues(t, 0, h.term.calls.Load())
	assert.EqualValues(t, 0, h.mark.calls.Load())

	// No injected credential appears anywhere in the recording.
	all := string(got.data[bsr.Inbound]) + string(got.data[bsr.Outbound]) + fmt.Sprint(got.reqTypes)
	assert.False(t, strings.Contains(all, testUpstreamPass))
	_, err = h.store.Path(recSessionId)
	require.NoError(t, err)
}

func TestRecordingUpstream_RecordsTargetRequests(t *testing.T) {
	ctx := context.Background()
	pt := newPtyTarget(t)
	inner, err := NewClientUpstream(ctx, pt.addr,
		injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
		ssh.FixedHostKey(pt.hostKey.PublicKey()))
	require.NoError(t, err)
	h, cu := newRecHarness(t, 1<<24, 1<<22, inner)
	ru, err := NewRecordingUpstream(ctx, cu, h.deps)
	require.NoError(t, err)
	conn, err := ru.Dial(ctx)
	require.NoError(t, err)

	ch, reqs, err := conn.OpenChannel("session", nil)
	require.NoError(t, err)
	ok, err := ch.SendRequest("pty-req", true, ssh.Marshal(struct {
		Term          string
		Cols, Rows    uint32
		Width, Height uint32
		Modes         string
	}{Term: "xterm", Cols: 80, Rows: 24}))
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = ch.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{"cat"}))
	require.NoError(t, err)
	require.True(t, ok)
	_, err = ch.Write([]byte("hello\n"))
	require.NoError(t, err)
	buf := make([]byte, len("hello\n"))
	_, err = io.ReadFull(ch, buf)
	require.NoError(t, err)
	_, err = ch.SendRequest("window-change", false, ssh.Marshal(struct{ Cols, Rows, Width, Height uint32 }{100, 40, 0, 0}))
	require.NoError(t, err)
	require.NoError(t, ch.CloseWrite())

	// The target sends exit-status once its input is closed; it is delivered
	// only after it has been recorded.
	select {
	case r, open := <-reqs:
		require.True(t, open)
		assert.Equal(t, "exit-status", r.Type)
	case <-time.After(10 * time.Second):
		t.Fatal("exit-status was not delivered")
	}
	// The target has already closed the channel and the connection, so these
	// may report that; finalisation of the recording must still succeed.
	_ = ch.Close()
	_ = conn.Close()
	require.NoError(t, conn.(interface{ FinalizeErr() error }).FinalizeErr())

	got := readBack(t, h)
	assert.Equal(t, []string{"HEAD", "PTYR", "EXEC", "WCHG", "DONE"}, got.reqTypes[bsr.Inbound])
	assert.Equal(t, []string{"HEAD", "EXST", "DONE"}, got.reqTypes[bsr.Outbound])
	assert.Equal(t, "hello\n", string(got.data[bsr.Inbound]))
	assert.Equal(t, "hello\n", string(got.data[bsr.Outbound]))
}

func TestRecordingUpstream_QuotaExhaustionTerminatesSession(t *testing.T) {
	ft := newFakeTarget(t)
	// Enough room for the session and channel scaffolding but not for bulk data.
	h, cu := newRecHarness(t, 64<<10, 8<<10, ft)
	ru, err := NewRecordingUpstream(context.Background(), cu, h.deps)
	require.NoError(t, err)

	client, done := startServe(t, context.Background(), okAuth(), ru)
	closeClient := func() { _ = client.Close() }
	h.term.onTerminate.Store(&closeClient)
	sess, err := client.NewSession()
	require.NoError(t, err)
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Start("cat"))
	// Random data does not compress below the quota.
	chunk := make([]byte, 16<<10)
	_, err = rand.Read(chunk)
	require.NoError(t, err)
	go func() {
		for i := 0; i < 64; i++ {
			if _, err := stdin.Write(chunk); err != nil {
				return
			}
		}
	}()
	// The terminator disconnects the client, so its session ends.
	waited := make(chan error, 1)
	go func() { waited <- sess.Wait() }()
	select {
	case <-waited:
	case <-time.After(15 * time.Second):
		t.Fatalf("client session was not closed after the recording failed: term=%d mark=%d used=%d", h.term.calls.Load(), h.mark.calls.Load(), h.store.Used())
	}
	require.Eventually(t, func() bool { return h.term.calls.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return")
	}
	assert.EqualValues(t, 1, h.term.calls.Load(), "terminator called exactly once")
	assert.EqualValues(t, 1, h.mark.calls.Load(), "recording marked incomplete exactly once")

	// Finalisation after a failure does not hide the failure.
	err = h.rec.Close()
	require.Error(t, err)
}

type failingTerminator struct{ err error }

func (f failingTerminator) Terminate(context.Context, string) error { return f.err }

func TestRecordingUpstream_FinalisationFailureIsSurfaced(t *testing.T) {
	ft := newFakeTarget(t)
	var failWrites atomic.Bool
	h, cu := newRecHarness(t, 1<<24, 1<<22, ft)
	h.fs.onWrite = func(p []byte) error {
		if failWrites.Load() {
			return errors.New("disk gone")
		}
		return nil
	}
	ru, err := NewRecordingUpstream(context.Background(), cu, h.deps)
	require.NoError(t, err)
	conn, err := ru.Dial(context.Background())
	require.NoError(t, err)
	ch, reqs, err := conn.OpenChannel("session", nil)
	require.NoError(t, err)
	go ssh.DiscardRequests(reqs)
	_, err = ch.Write([]byte("x"))
	require.NoError(t, err)

	failWrites.Store(true)
	err = conn.Close()
	require.Error(t, err, "finalisation failure must be returned from Close")
	assert.Contains(t, err.Error(), "finalising recording")
	assert.EqualValues(t, 1, h.mark.calls.Load())
	assert.EqualValues(t, 1, h.term.calls.Load())
	assert.Error(t, conn.(interface{ FinalizeErr() error }).FinalizeErr())
}
