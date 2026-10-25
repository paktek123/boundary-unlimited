// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package recorder

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/convert"
	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	bssh "github.com/hashicorp/boundary/internal/bsr/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

const (
	sessionId    = "s_1234567890"
	recordingId  = "sr_1234567890"
	connectionId = "cr_1234567890"
	channelId    = "chr_1234567890"
)

func newSession(t *testing.T, fs *fstest.MemFS) (*bsr.Session, kms.KeyUnwrapCallbackFunc) {
	t.Helper()
	ctx := context.Background()
	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sessionId)
	require.NoError(t, err)
	keyFn := func(kms.WrappedKeys) (kms.UnwrappedKeys, error) {
		return kms.UnwrappedKeys{BsrKey: keys.BsrKey, PrivKey: keys.PrivKey}, nil
	}
	s, err := bsr.NewSession(ctx, &bsr.SessionRecordingMeta{Id: recordingId, Protocol: bssh.Protocol},
		bsr.TestSessionMeta(sessionId), fs, keys, bsr.WithSupportsMultiplex(true))
	require.NoError(t, err)
	return s, keyFn
}

func ptyPayload() []byte {
	return gssh.Marshal(struct {
		Term       string
		Cols, Rows uint32
		Wpix, Hpix uint32
		Modes      string
	}{"xterm", 80, 24, 0, 0, ""})
}

func TestRecorder_RoundTrip(t *testing.T) {
	ctx := context.Background()
	fs := &fstest.MemFS{}
	sess, keyFn := newSession(t, fs)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tick := func() time.Time { now = now.Add(time.Millisecond); return now }

	rec, err := NewRecorder(ctx, sess, connectionId, WithClock(tick))
	require.NoError(t, err)
	ch, err := rec.Channel("session", channelId)
	require.NoError(t, err)

	require.NoError(t, ch.WriteRequest(bsr.Inbound, &gssh.Request{Type: "pty-req", WantReply: true, Payload: ptyPayload()}))
	require.NoError(t, ch.WriteRequest(bsr.Inbound, &gssh.Request{Type: "shell", WantReply: true}))
	require.NoError(t, ch.WriteRequest(bsr.Inbound, &gssh.Request{Type: "weird@example.com", Payload: []byte("x")}))
	require.NoError(t, ch.WriteData(bsr.Inbound, []byte("ls\n")))
	require.NoError(t, ch.WriteData(bsr.Outbound, []byte("hello world\n")))
	// larger than one chunk is split, not rejected
	big := make([]byte, bssh.MaxPacketSize+10)
	require.NoError(t, ch.WriteData(bsr.Outbound, big))

	require.NoError(t, rec.Close())
	require.NoError(t, rec.Close(), "Close is idempotent")
	require.NoError(t, ch.Close(), "channel Close is idempotent")

	require.NoError(t, sess.EncodeSummary(ctx, &bsr.BaseSessionSummary{Id: recordingId, ConnectionCount: 1}))
	require.NoError(t, sess.Close(ctx))

	v, err := bsr.Validate(ctx, recordingId, fs, keyFn)
	require.NoError(t, err)
	require.True(t, v.Valid, "BSR must validate: %+v", v)

	opened, err := bsr.OpenSession(ctx, recordingId, fs, keyFn)
	require.NoError(t, err)
	defer opened.Close(ctx)
	conn, err := opened.OpenConnection(ctx, connectionId)
	require.NoError(t, err)
	defer conn.Close(ctx)
	assert.EqualValues(t, 1, conn.Summary.(*bsr.BaseConnectionSummary).ChannelCount)
	assert.EqualValues(t, 3, conn.Summary.(*bsr.BaseConnectionSummary).BytesUp)
	assert.EqualValues(t, 12+bssh.MaxPacketSize+10, conn.Summary.(*bsr.BaseConnectionSummary).BytesDown)
	oc, err := conn.OpenChannel(ctx, channelId)
	require.NoError(t, err)
	defer oc.Close(ctx)
	cs := oc.Summary.(*bssh.ChannelSummary)
	assert.Equal(t, bssh.Shell, cs.SessionProgram)

	// request chunks decode back to their types
	sc, err := oc.OpenRequestScanner(ctx, bsr.Inbound)
	require.NoError(t, err)
	defer sc.Close()
	var types []string
	for {
		c, err := sc.Scan(ctx)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		types = append(types, string(c.GetType()))
	}
	assert.Equal(t, []string{"HEAD", "PTYR", "SHLL", "UNKR", "DONE"}, types)

	// the existing converter can read what we recorded
	tmp, err := fstest.NewTempFile(t.Name())
	require.NoError(t, err)
	defer tmp.Close()
	rc, err := convert.ToAsciicast(ctx, opened, tmp, connectionId, convert.WithChannelId(channelId))
	require.NoError(t, err)
	out, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Contains(t, string(out), "hello world")
	assert.Contains(t, string(out), `"version":2`)
}

func TestRecorder_InvalidArgs(t *testing.T) {
	ctx := context.Background()
	sess, _ := newSession(t, &fstest.MemFS{})
	_, err := NewRecorder(ctx, nil, connectionId)
	assert.ErrorIs(t, err, bsr.ErrInvalidParameter)
	_, err = NewRecorder(ctx, sess, "")
	assert.ErrorIs(t, err, bsr.ErrInvalidParameter)

	rec, err := NewRecorder(ctx, sess, connectionId)
	require.NoError(t, err)
	_, err = rec.Channel("", channelId)
	assert.ErrorIs(t, err, bsr.ErrInvalidParameter)
	ch, err := rec.Channel("session", channelId)
	require.NoError(t, err)
	assert.ErrorIs(t, ch.WriteData(bsr.UnknownDirection, []byte("x")), bsr.ErrInvalidParameter)
	assert.ErrorIs(t, ch.WriteRequest(bsr.Inbound, nil), bsr.ErrInvalidParameter)
	require.NoError(t, rec.Close())
}

func TestRecorder_WriteAfterCloseFails(t *testing.T) {
	ctx := context.Background()
	sess, _ := newSession(t, &fstest.MemFS{})
	rec, err := NewRecorder(ctx, sess, connectionId)
	require.NoError(t, err)
	ch, err := rec.Channel("session", channelId)
	require.NoError(t, err)
	require.NoError(t, ch.Close())
	assert.Error(t, ch.WriteData(bsr.Inbound, []byte("late")))
	assert.Error(t, ch.WriteRequest(bsr.Inbound, &gssh.Request{Type: "shell"}))
	require.NoError(t, rec.Close())
	_, err = rec.Channel("session", "another")
	assert.Error(t, err, "no channels after Close")
}

func TestRecorder_StorageFailureIsSticky(t *testing.T) {
	ctx := context.Background()
	fs := fstest.NewLimitedSpaceFS()
	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sessionId)
	require.NoError(t, err)
	sess, err := bsr.NewSession(ctx, &bsr.SessionRecordingMeta{Id: recordingId, Protocol: bssh.Protocol},
		bsr.TestSessionMeta(sessionId), fs, keys, bsr.WithSupportsMultiplex(true))
	require.NoError(t, err)
	rec, err := NewRecorder(ctx, sess, connectionId)
	require.NoError(t, err)

	// Closing the underlying writer simulates a failing store: encoding an
	// end chunk closes it, so further writes through the same writer fail.
	ch, err := rec.Channel("session", channelId)
	require.NoError(t, err)
	require.NoError(t, ch.messages[bsr.Inbound].w.(io.Closer).Close())
	err = ch.WriteData(bsr.Inbound, []byte("data"))
	require.Error(t, err, "write error must surface so the caller can terminate the session")
	assert.Error(t, ch.WriteData(bsr.Outbound, []byte("other direction")), "error is sticky")
	_, cerr := rec.Channel("session", "next")
	assert.NoError(t, cerr, "recorder-level state is unaffected by a channel-level error")
	assert.Error(t, ch.Close(), "Close reports the first error")
	cerr = rec.Close()
	require.Error(t, cerr, "connection close surfaces channel error")
	assert.Contains(t, cerr.Error(), "recorder.(ChannelRecorder)")
}
