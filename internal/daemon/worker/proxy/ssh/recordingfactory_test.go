// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	bssh "github.com/hashicorp/boundary/internal/bsr/ssh"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/finalize"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeFinalizer struct {
	calls atomic.Int32
	err   error
}

func (f *fakeFinalizer) Finalize(context.Context, string) (upload.Result, error) {
	f.calls.Add(1)
	return upload.Result{Status: upload.StatusUploaded}, f.err
}

type fakeFinalizeReporter struct {
	mu   sync.Mutex
	errs []error
}

func (r *fakeFinalizeReporter) RecordingFinalized(_ context.Context, _ string, _ upload.Result, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
}

type fakeSpecs struct {
	t        *testing.T
	capacity int64
	term     *fakeTerminator
	mark     *fakeMarker
	err      error
}

func (s *fakeSpecs) RecordingSpec(ctx context.Context, auth Authorization) (SessionRecordingSpec, error) {
	if s.err != nil {
		return SessionRecordingSpec{}, s.err
	}
	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(s.t), auth.SessionId)
	require.NoError(s.t, err)
	return SessionRecordingSpec{
		Meta:         &bsr.SessionRecordingMeta{Id: "sr_1234567890", Protocol: bssh.Protocol},
		SessionMeta:  bsr.TestSessionMeta(auth.SessionId),
		Keys:         keys,
		ConnectionId: recConnId,
		Capacity:     s.capacity,
		Terminator:   s.term,
		Marker:       s.mark,
	}, nil
}

type factoryHarness struct {
	store *scratch.Store
	fin   *fakeFinalizer
	rep   *fakeFinalizeReporter
	specs *fakeSpecs
	deps  RecordingFactoryDeps
}

func newFactoryHarness(t *testing.T, quota, capacity int64) *factoryHarness {
	t.Helper()
	store, err := scratch.New(t.TempDir(), quota)
	require.NoError(t, err)
	h := &factoryHarness{store: store, fin: &fakeFinalizer{}, rep: &fakeFinalizeReporter{}}
	h.specs = &fakeSpecs{t: t, capacity: capacity, term: &fakeTerminator{}, mark: &fakeMarker{}}
	h.deps = RecordingFactoryDeps{Scratch: store, Finalizer: h.fin, Specs: h.specs, Reporter: h.rep}
	return h
}

func TestNewRecordingFactory_NilDependency(t *testing.T) {
	h := newFactoryHarness(t, 1<<20, 1<<18)
	for name, mod := range map[string]func(*RecordingFactoryDeps){
		"scratch":   func(d *RecordingFactoryDeps) { d.Scratch = nil },
		"finalizer": func(d *RecordingFactoryDeps) { d.Finalizer = nil },
		"specs":     func(d *RecordingFactoryDeps) { d.Specs = nil },
		"reporter":  func(d *RecordingFactoryDeps) { d.Reporter = nil },
	} {
		t.Run(name, func(t *testing.T) {
			d := h.deps
			mod(&d)
			f, err := NewRecordingFactory(d)
			require.Error(t, err)
			assert.Nil(t, f)
		})
	}
	f, err := NewRecordingFactory(h.deps)
	require.NoError(t, err)
	require.NotNil(t, f)
}

func TestRecordingFactory_HappyPathFinalisesOnceOnClose(t *testing.T) {
	ctx := context.Background()
	h := newFactoryHarness(t, 4<<20, 1<<20)
	f, err := NewRecordingFactory(h.deps)
	require.NoError(t, err)
	ft := newFakeTarget(t)
	up, err := f.Wrap(ctx, okAuth(), ft)
	require.NoError(t, err)
	assert.EqualValues(t, 0, ft.dials.Load(), "Wrap must not dial")

	conn, err := up.Dial(ctx)
	require.NoError(t, err)
	ch, _, err := conn.OpenChannel("session", nil)
	require.NoError(t, err)
	_, err = ch.Write([]byte("hello"))
	require.NoError(t, err)
	assert.EqualValues(t, 0, h.fin.calls.Load(), "not finalised before close")

	// BSR bytes were written into the scratch store.
	dir, err := h.store.Path(okAuth().SessionId)
	require.NoError(t, err)
	assert.NotEmpty(t, dir)
	assert.NotZero(t, h.store.Used())

	require.NoError(t, conn.Close())
	require.NoError(t, conn.Close(), "close is idempotent")
	assert.EqualValues(t, 1, h.fin.calls.Load())
	require.Len(t, h.rep.errs, 1)
	assert.NoError(t, h.rep.errs[0])
	assert.Zero(t, h.specs.mark.calls.Load())
}

func TestRecordingFactory_FinalizeFailureIsReportedAndReturned(t *testing.T) {
	ctx := context.Background()
	h := newFactoryHarness(t, 4<<20, 1<<20)
	h.fin.err = errors.New("upload failed")
	f, err := NewRecordingFactory(h.deps)
	require.NoError(t, err)
	up, err := f.Wrap(ctx, okAuth(), newFakeTarget(t))
	require.NoError(t, err)
	conn, err := up.Dial(ctx)
	require.NoError(t, err)
	err = conn.Close()
	require.ErrorIs(t, err, h.fin.err)
	require.Len(t, h.rep.errs, 1)
	assert.ErrorIs(t, h.rep.errs[0], h.fin.err)
	_, perr := h.store.Path(okAuth().SessionId)
	assert.NoError(t, perr, "scratch data must be kept when finalisation fails")
}

func TestRecordingFactory_QuotaExceededRejectsBeforeDial(t *testing.T) {
	ctx := context.Background()
	h := newFactoryHarness(t, 10, 1<<20)
	f, err := NewRecordingFactory(h.deps)
	require.NoError(t, err)
	ft := newFakeTarget(t)
	up, err := f.Wrap(ctx, okAuth(), ft)
	require.ErrorIs(t, err, scratch.ErrQuotaExceeded)
	assert.Nil(t, up)
	assert.EqualValues(t, 0, ft.dials.Load())
	assert.EqualValues(t, 0, h.fin.calls.Load())
}

func TestRecordingFactory_SpecErrorsRejectAndReserveNothing(t *testing.T) {
	ctx := context.Background()
	h := newFactoryHarness(t, 4<<20, 1<<20)
	h.specs.err = errors.New("no keys")
	f, err := NewRecordingFactory(h.deps)
	require.NoError(t, err)
	_, err = f.Wrap(ctx, okAuth(), newFakeTarget(t))
	require.Error(t, err)
	assert.Zero(t, h.store.Used())
	_, err = f.Wrap(ctx, okAuth(), nil)
	require.Error(t, err)
}

func TestRecordingFactory_WriteFailureTerminatesAndKeepsScratch(t *testing.T) {
	ctx := context.Background()
	// Reserve almost nothing beyond the BSR meta files so data writes exceed
	// the quota mid-session.
	store, err := scratch.New(t.TempDir(), 64<<10)
	require.NoError(t, err)
	h := newFactoryHarness(t, 64<<10, 8<<10)
	h.store = store
	h.deps.Scratch = store
	// Use the real finalizer so an incomplete recording cannot be finished.
	h.deps.Finalizer = realFinalizer{store: store}
	f, err := NewRecordingFactory(h.deps)
	require.NoError(t, err)
	up, err := f.Wrap(ctx, okAuth(), newFakeTarget(t))
	require.NoError(t, err)
	conn, err := up.Dial(ctx)
	require.NoError(t, err)
	ch, _, err := conn.OpenChannel("session", nil)
	require.NoError(t, err)
	chunk := make([]byte, 16<<10)
	_, err = rand.Read(chunk)
	require.NoError(t, err)
	var werr error
	for i := 0; i < 16 && werr == nil; i++ {
		_, werr = ch.Write(chunk)
	}
	require.Error(t, werr, "recording failure must stop the session's writes")
	assert.EqualValues(t, 1, h.specs.term.calls.Load())
	assert.EqualValues(t, 1, h.specs.mark.calls.Load())

	err = conn.Close()
	require.Error(t, err, "an incomplete recording cannot be finalised")
	_, perr := store.Path(okAuth().SessionId)
	assert.NoError(t, perr, "scratch data must be kept for orphan recovery")
}

// realFinalizer finishes recordings with the real scratch store and a
// submitter that must not be reached for incomplete recordings.
type realFinalizer struct{ store *scratch.Store }

func (r realFinalizer) Finalize(ctx context.Context, id string) (upload.Result, error) {
	f, err := finalize.New(r.store, okSubmitter{})
	if err != nil {
		return upload.Result{}, err
	}
	return f.Finalize(ctx, id)
}

type okSubmitter struct{}

func (okSubmitter) Submit(context.Context, upload.Recording) upload.Result {
	return upload.Result{Status: upload.StatusUploaded}
}
