// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package playback

import (
	"bytes"
	"context"
	"errors"
	"io"
)

var (
	// ErrInvalidRecording is returned when validation fails or reports the
	// recording as invalid.
	ErrInvalidRecording = errors.New("playback: invalid recording")
	// ErrIncompleteRecording is returned when the recording is valid but
	// reported as incomplete.
	ErrIncompleteRecording = errors.New("playback: incomplete recording")
	// ErrConversionFailed is returned when the converter fails or its output
	// cannot be read in full. The underlying error is deliberately dropped,
	// since it could echo recording content.
	ErrConversionFailed = errors.New("playback: conversion failed")
	// ErrOutputTooLarge is returned when converted output exceeds the limit.
	ErrOutputTooLarge = errors.New("playback: converted output too large")
	// ErrInvalidParameter is returned for missing arguments.
	ErrInvalidParameter = errors.New("playback: invalid parameter")
)

// Format is an export format.
type Format string

const (
	// Asciicast is asciicast v2, used for shell channels.
	Asciicast Format = "asciicast"
	// RawLog is the raw channel log, used for all other channel types.
	RawLog Format = "raw"
)

// ShellChannelType is the channel type exported as asciicast.
const ShellChannelType = "shell"

// Source identifies the recording (channel) to export.
type Source interface {
	// ChannelType returns the SSH channel type of the recording.
	ChannelType(ctx context.Context) (string, error)
}

// Result is the outcome of validating a recording.
type Result struct {
	Valid    bool
	Complete bool
}

// Validator validates a recording before it is converted.
type Validator interface {
	Validate(ctx context.Context, src Source) (Result, error)
}

// Converter converts a validated recording into the requested format.
type Converter interface {
	Convert(ctx context.Context, src Source, f Format) (io.ReadCloser, error)
}

// Export validates src and, only if it is valid and complete, converts it and
// writes the result to dst. On any error nothing has been written to dst.
func Export(ctx context.Context, src Source, v Validator, c Converter, dst io.Writer, opt ...Option) error {
	if isNil(src) || isNil(v) || isNil(c) || isNil(dst) {
		return ErrInvalidParameter
	}
	opts := getOpts(opt...)

	if err := ctx.Err(); err != nil {
		return err
	}
	res, err := v.Validate(ctx, src)
	switch {
	case err != nil:
		// The validator's error is not wrapped: it could echo content.
		return ErrInvalidRecording
	case !res.Valid:
		return ErrInvalidRecording
	case !res.Complete:
		return ErrIncompleteRecording
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	ct, err := src.ChannelType(ctx)
	if err != nil {
		return ErrConversionFailed
	}
	format := RawLog
	if ct == ShellChannelType {
		format = Asciicast
	}

	rc, err := c.Convert(ctx, src, format)
	if err != nil || isNil(rc) {
		return ErrConversionFailed
	}
	defer rc.Close()

	// Buffer the output, reading one byte past the limit to detect overflow.
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(&ctxReader{ctx: ctx, r: rc}, opts.maxBytes+1))
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	if err != nil {
		return ErrConversionFailed
	}
	if n > opts.maxBytes {
		return ErrOutputTooLarge
	}

	if _, err := dst.Write(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

// ctxReader stops reading once the context is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
