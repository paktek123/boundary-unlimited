// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package masking is a pure-Go streaming redactor for session data. It is a
// standalone library: nothing in the controller or worker uses it yet, so it
// enables no capability.
package masking

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// DefaultMaxPatternLen is the default longest match (and lookbehind) in bytes.
const DefaultMaxPatternLen = 4096

// DefaultReplacement is the default replacement template; "{detector}" is
// replaced by the detector name.
const DefaultReplacement = "[REDACTED:{detector}]"

// Errors. After any error the Redactor is failed: all later calls return an
// error and no held bytes are ever written.
var (
	ErrBufferLimit = errors.New("masking: sensitive data exceeds the maximum pattern length")
	ErrClosed      = errors.New("masking: redactor is closed")
)

type options struct {
	maxLen      int
	replacement string
	detectors   []Detector
}

// Option configures a Redactor.
type Option func(*options)

// WithMaxPatternLen sets the maximum match length and lookbehind size.
func WithMaxPatternLen(n int) Option { return func(o *options) { o.maxLen = n } }

// WithReplacement sets the replacement template ("{detector}" is substituted).
func WithReplacement(t string) Option { return func(o *options) { o.replacement = t } }

// WithDetectors replaces the default detector set.
func WithDetectors(d ...Detector) Option { return func(o *options) { o.detectors = d } }

// Redactor wraps an io.Writer and redacts sensitive data, including data
// split across Write calls, by holding back the last MaxPatternLen bytes
// until more data arrives or Close is called. It is not safe for concurrent
// use. Digit runs are re-scanned from the start of the held buffer, so the
// tail of a very long digit string may be redacted as a card number: a false
// positive, which is the safe direction.
//
// Fail closed: if a detector panics or returns invalid spans, a match exceeds
// the maximum pattern length, or the underlying writer fails, Write returns an
// error, held bytes are discarded and nothing unredacted is passed through.
type Redactor struct {
	w       io.Writer
	opt     options
	pending []byte
	err     error
}

// New returns a Redactor writing to w.
func New(w io.Writer, opt ...Option) (*Redactor, error) {
	if w == nil {
		return nil, errors.New("masking: writer is required")
	}
	o := options{maxLen: DefaultMaxPatternLen, replacement: DefaultReplacement}
	for _, f := range opt {
		f(&o)
	}
	if o.maxLen <= 0 {
		return nil, errors.New("masking: max pattern length must be positive")
	}
	if o.detectors == nil {
		o.detectors = DefaultDetectors()
	}
	for _, d := range o.detectors {
		if d == nil {
			return nil, errors.New("masking: nil detector")
		}
	}
	return &Redactor{w: w, opt: o}, nil
}

// Write implements io.Writer. It reports len(p) on success even though some
// bytes are held back until later.
func (r *Redactor) Write(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	r.pending = append(r.pending, p...)
	if err := r.process(false); err != nil {
		return 0, r.fail(err)
	}
	return len(p), nil
}

// Flush ends the stream: it scans the held bytes one last time, writes them
// and makes the Redactor reject further writes. An unterminated private key
// block is redacted to the end of the input.
func (r *Redactor) Flush() error { return r.Close() }

// Close is the same as Flush. It does not close the underlying writer.
func (r *Redactor) Close() error {
	if r.err != nil {
		if errors.Is(r.err, ErrClosed) {
			return nil
		}
		return r.err
	}
	if err := r.process(true); err != nil {
		return r.fail(err)
	}
	r.err = ErrClosed
	return nil
}

func (r *Redactor) fail(err error) error {
	r.pending = nil
	r.err = err
	return err
}

type named struct {
	Span
	name string
}

// scan returns merged spans (earliest start wins, overlaps merge, name of the
// first span) and the offset of the earliest unterminated construct or -1.
func (r *Redactor) scan(b []byte) (spans []named, partial int, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("masking: detector panic: %v", p)
		}
	}()
	partial = -1
	var all []named
	for _, d := range r.opt.detectors {
		for _, s := range d.Find(b) {
			if s.Start < 0 || s.End > len(b) || s.Start >= s.End {
				return nil, -1, fmt.Errorf("masking: detector %q returned an invalid span", d.Name())
			}
			all = append(all, named{s, d.Name()})
		}
		if pd, ok := d.(partialDetector); ok {
			if i := pd.Partial(b); i >= 0 && (partial < 0 || i < partial) {
				partial = i
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Start < all[j].Start })
	for _, s := range all {
		if n := len(spans); n > 0 && s.Start < spans[n-1].End {
			if s.End > spans[n-1].End {
				spans[n-1].End = s.End
			}
			continue
		}
		spans = append(spans, s)
	}
	return spans, partial, nil
}

func (r *Redactor) process(final bool) error {
	if len(r.pending) == 0 {
		return nil
	}
	spans, partial, err := r.scan(r.pending)
	if err != nil {
		return err
	}
	n := len(r.pending)
	hold := n
	if !final {
		hold = n - r.opt.maxLen
		if hold < 0 {
			hold = 0
		}
		if partial >= 0 {
			if n-partial > r.opt.maxLen {
				return ErrBufferLimit
			}
			if partial < hold {
				hold = partial
			}
		}
	} else if partial >= 0 {
		spans = append(spans, named{Span{partial, n}, "private_key"})
		sort.SliceStable(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
		merged := spans[:0]
		for _, s := range spans {
			if m := len(merged); m > 0 && s.Start < merged[m-1].End {
				if s.End > merged[m-1].End {
					merged[m-1].End = s.End
				}
				continue
			}
			merged = append(merged, s)
		}
		spans = merged
	}
	for _, s := range spans {
		if s.End-s.Start > r.opt.maxLen {
			return ErrBufferLimit
		}
		if s.Start < hold && s.End > hold {
			hold = s.Start
		}
	}
	var out []byte
	pos := 0
	for _, s := range spans {
		if s.End > hold {
			break
		}
		out = append(out, r.pending[pos:s.Start]...)
		out = append(out, strings.ReplaceAll(r.opt.replacement, "{detector}", s.name)...)
		pos = s.End
	}
	out = append(out, r.pending[pos:hold]...)
	if len(out) > 0 {
		if _, err := r.w.Write(out); err != nil {
			return fmt.Errorf("masking: write: %w", err)
		}
	}
	r.pending = append(r.pending[:0], r.pending[hold:]...)
	return nil
}
