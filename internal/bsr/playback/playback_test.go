// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package playback

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secret = "hunter2-TYPED-PASSWORD"

type fakeSource struct {
	ct  string
	err error
}

func (s fakeSource) ChannelType(context.Context) (string, error) { return s.ct, s.err }

type fakeValidator struct {
	res   Result
	err   error
	calls int
}

func (v *fakeValidator) Validate(context.Context, Source) (Result, error) {
	v.calls++
	return v.res, v.err
}

type fakeConverter struct {
	out     func() io.Reader
	err     error
	calls   int
	formats []Format
	closed  bool
}

func (c *fakeConverter) Convert(_ context.Context, _ Source, f Format) (io.ReadCloser, error) {
	c.calls++
	c.formats = append(c.formats, f)
	if c.err != nil {
		return nil, c.err
	}
	return &closer{Reader: c.out(), c: c}, nil
}

type closer struct {
	io.Reader
	c *fakeConverter
}

func (c *closer) Close() error { c.c.closed = true; return nil }

// failAfter yields data and then an error.
type failAfter struct {
	data string
	err  error
	done bool
}

func (f *failAfter) Read(p []byte) (int, error) {
	if f.done {
		return 0, f.err
	}
	f.done = true
	return copy(p, f.data), nil
}

func valid() Result { return Result{Valid: true, Complete: true} }

func str(s string) func() io.Reader { return func() io.Reader { return strings.NewReader(s) } }

func TestExport(t *testing.T) {
	tests := []struct {
		name        string
		src         fakeSource
		val         *fakeValidator
		conv        *fakeConverter
		opts        []Option
		wantErr     error
		wantOut     string
		wantConvert int
		wantFormat  Format
	}{
		{"valid shell exports asciicast", fakeSource{ct: "shell"}, &fakeValidator{res: valid()}, &fakeConverter{out: str("CAST")}, nil, nil, "CAST", 1, Asciicast},
		{"valid exec exports raw log", fakeSource{ct: "exec"}, &fakeValidator{res: valid()}, &fakeConverter{out: str("RAW")}, nil, nil, "RAW", 1, RawLog},
		{"invalid", fakeSource{ct: "shell"}, &fakeValidator{res: Result{Valid: false, Complete: true}}, &fakeConverter{out: str("x")}, nil, ErrInvalidRecording, "", 0, ""},
		{"incomplete", fakeSource{ct: "shell"}, &fakeValidator{res: Result{Valid: true, Complete: false}}, &fakeConverter{out: str("x")}, nil, ErrIncompleteRecording, "", 0, ""},
		{"validator error", fakeSource{ct: "shell"}, &fakeValidator{err: errors.New("bad " + secret)}, &fakeConverter{out: str("x")}, nil, ErrInvalidRecording, "", 0, ""},
		{"channel type error", fakeSource{err: errors.New(secret)}, &fakeValidator{res: valid()}, &fakeConverter{out: str("x")}, nil, ErrConversionFailed, "", 0, ""},
		{"converter start error", fakeSource{ct: "shell"}, &fakeValidator{res: valid()}, &fakeConverter{err: errors.New(secret)}, nil, ErrConversionFailed, "", 1, Asciicast},
		{"converter error mid-stream", fakeSource{ct: "shell"}, &fakeValidator{res: valid()}, &fakeConverter{out: func() io.Reader { return &failAfter{data: "partial", err: errors.New(secret)} }}, nil, ErrConversionFailed, "", 1, Asciicast},
		{"output too large", fakeSource{ct: "shell"}, &fakeValidator{res: valid()}, &fakeConverter{out: str("0123456789")}, []Option{WithMaxBytes(5)}, ErrOutputTooLarge, "", 1, Asciicast},
		{"output exactly at limit", fakeSource{ct: "shell"}, &fakeValidator{res: valid()}, &fakeConverter{out: str("01234")}, []Option{WithMaxBytes(5)}, nil, "01234", 1, Asciicast},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dst bytes.Buffer
			err := Export(context.Background(), tt.src, tt.val, tt.conv, &dst, tt.opts...)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.NotContains(t, err.Error(), secret)
				assert.NotContains(t, err.Error(), "partial")
				assert.Zero(t, dst.Len(), "nothing written to dst on error")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantOut, dst.String())
			}
			assert.Equal(t, tt.wantConvert, tt.conv.calls)
			if tt.wantConvert > 0 {
				assert.Equal(t, tt.wantFormat, tt.conv.formats[0])
				if tt.conv.err == nil {
					assert.True(t, tt.conv.closed, "converter output closed")
				}
			}
		})
	}
}

func TestConverterNeverCalledWhenValidationFails(t *testing.T) {
	for _, res := range []Result{{}, {Valid: false, Complete: true}, {Valid: true, Complete: false}} {
		conv := &fakeConverter{out: str("x")}
		var dst bytes.Buffer
		require.Error(t, Export(context.Background(), fakeSource{ct: "shell"}, &fakeValidator{res: res}, conv, &dst))
		assert.Zero(t, conv.calls)
		assert.Zero(t, dst.Len())
	}
}

func TestExportContextCancellation(t *testing.T) {
	t.Run("cancelled before validation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		val := &fakeValidator{res: valid()}
		var dst bytes.Buffer
		err := Export(ctx, fakeSource{ct: "shell"}, val, &fakeConverter{out: str("x")}, &dst)
		require.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, val.calls)
		assert.Zero(t, dst.Len())
	})
	t.Run("cancelled during conversion", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		conv := &fakeConverter{out: func() io.Reader { cancel(); return strings.NewReader("data") }}
		var dst bytes.Buffer
		err := Export(ctx, fakeSource{ct: "shell"}, &fakeValidator{res: valid()}, conv, &dst)
		require.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, dst.Len())
	})
}

func TestExportRejectsNilArguments(t *testing.T) {
	var nilSrc *fakeSource
	ok := func() (Source, Validator, Converter, io.Writer) {
		return fakeSource{ct: "shell"}, &fakeValidator{res: valid()}, &fakeConverter{out: str("x")}, &bytes.Buffer{}
	}
	s, v, c, d := ok()
	assert.ErrorIs(t, Export(context.Background(), nil, v, c, d), ErrInvalidParameter)
	assert.ErrorIs(t, Export(context.Background(), nilSrc, v, c, d), ErrInvalidParameter)
	assert.ErrorIs(t, Export(context.Background(), s, nil, c, d), ErrInvalidParameter)
	assert.ErrorIs(t, Export(context.Background(), s, v, nil, d), ErrInvalidParameter)
	assert.ErrorIs(t, Export(context.Background(), s, v, c, nil), ErrInvalidParameter)
}
