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

// chunkFactor sizes the input chunks relative to MaxPatternLen: Write feeds
// input in chunks of chunkFactor*MaxPatternLen bytes. Chunks are large so a
// match up to MaxPatternLen is never cut. The held buffer is therefore bounded
// by the carried bytes (at most about 2*MaxPatternLen: lookbehind plus an
// unterminated construct) plus one chunk, and its backing array by twice that
// when it grows.
const chunkFactor = 32

// MaxPatternLenLimit is the compile-time maximum accepted by
// WithMaxPatternLen. It bounds the memory held per Redactor: about
// (chunkFactor+2)*2 times the configured length for the backing array, i.e.
// roughly 4.5 MiB at the limit (intended budget).
const MaxPatternLenLimit = 1 << 16

// DefaultReplacement is the default replacement template; "{detector}" is
// replaced by the detector name.
const DefaultReplacement = "[REDACTED:{detector}]"

// Errors. After any error the Redactor is failed: all later calls return an
// error and no held bytes are ever written.
var (
	ErrBufferLimit = errors.New("masking: sensitive data exceeds the maximum pattern length")
	ErrClosed      = errors.New("masking: redactor is closed")
	// ErrInternal is returned after a detector or writer panic. It carries no
	// panic value or buffer content.
	ErrInternal = errors.New("masking: internal error while scanning; stream terminated")
)

type options struct {
	maxLen      int
	replacement string
	detectors   []Detector
	onRedact    func(detector string, n int)
}

// Option configures a Redactor.
type Option func(*options)

// WithMaxPatternLen sets the maximum match length and lookbehind size.
func WithMaxPatternLen(n int) Option { return func(o *options) { o.maxLen = n } }

// WithReplacement sets the replacement template ("{detector}" is substituted).
func WithReplacement(t string) Option { return func(o *options) { o.replacement = t } }

// WithDetectors replaces the default detector set.
func WithDetectors(d ...Detector) Option { return func(o *options) { o.detectors = d } }

// WithOnRedact registers a callback that receives, for every detector that
// replaced at least one match while processing a chunk, the detector name and
// the number of replacements. Only counts are reported: never the matched
// bytes, offsets or lengths. Each replacement is counted exactly once, even
// when the secret is split across Write calls, because a match is counted only
// when it is emitted. The callback is invoked synchronously, before the
// redacted output is written, in sorted detector order. Counts are therefore
// reported at most once per replacement but before delivery: if the
// underlying writer then fails, the count was reported for output that never
// reached it (the redactor is failed at that point). A panic in the callback
// is treated as a redactor failure (ErrInternal, held bytes wiped). A nil
// callback disables counting.
func WithOnRedact(f func(detector string, n int)) Option { return func(o *options) { o.onRedact = f } }

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
	if o.maxLen > MaxPatternLenLimit {
		return nil, errors.New("masking: max pattern length exceeds the compile-time maximum")
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
// bytes are held back until later. Input is consumed in chunks of at most
// MaxPatternLen bytes so the held buffer never exceeds a hard cap of about
// twice that length.
func (r *Redactor) Write(p []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	defer r.recoverPanic(&err)
	for off := 0; off < len(p); {
		end := off + chunkFactor*r.opt.maxLen
		if end > len(p) {
			end = len(p)
		}
		r.hold(p[off:end])
		if err = r.process(false); err != nil {
			return 0, r.fail(err)
		}
		off = end
	}
	return len(p), nil
}

// hold appends b to the pending buffer. When the backing array must grow the
// old one is zeroed so no plaintext is left behind.
func (r *Redactor) hold(b []byte) {
	if len(r.pending)+len(b) > cap(r.pending) {
		grown := make([]byte, len(r.pending), 2*(len(r.pending)+len(b)))
		copy(grown, r.pending)
		wipe(r.pending)
		r.pending = grown
	}
	r.pending = append(r.pending, b...)
}

// wipe overwrites the whole backing array of b with zeros (best effort: Go
// gives no guarantee about copies made by the runtime).
func wipe(b []byte) { clear(b[:cap(b)]) }

// recoverPanic turns a panic into ErrInternal without recording the panic
// value, discards held bytes and never emits unscanned data.
func (r *Redactor) recoverPanic(err *error) {
	if p := recover(); p != nil {
		*err = r.fail(ErrInternal)
	}
}

// Flush ends the stream: it scans the held bytes one last time, writes them
// and makes the Redactor reject further writes. An unterminated private key
// block is redacted to the end of the input.
func (r *Redactor) Flush() error { return r.Close() }

// Close is the same as Flush. It does not close the underlying writer.
func (r *Redactor) Close() (err error) {
	defer r.recoverPanic(&err)
	if r.err != nil {
		if errors.Is(r.err, ErrClosed) {
			return nil
		}
		return r.err
	}
	if err := r.process(true); err != nil {
		return r.fail(err)
	}
	wipe(r.pending)
	r.pending = nil
	r.err = ErrClosed
	return nil
}

func (r *Redactor) fail(err error) error {
	wipe(r.pending)
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
			err = ErrInternal // never include the panic value: it may hold buffer content
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
	var counts map[string]int
	for _, s := range spans {
		if s.End > hold {
			break
		}
		if r.opt.onRedact != nil {
			if counts == nil {
				counts = map[string]int{}
			}
			counts[s.name]++
		}
		out = append(out, r.pending[pos:s.Start]...)
		out = append(out, strings.ReplaceAll(r.opt.replacement, "{detector}", s.name)...)
		pos = s.End
	}
	out = append(out, r.pending[pos:hold]...)
	if len(counts) > 0 {
		names := make([]string, 0, len(counts))
		for k := range counts {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			// A panic here is recovered by Write/Close, which fail the
			// redactor and wipe held bytes; out is cleared by the defer below
			// only once registered, so clear it explicitly on this path.
			func() {
				defer func() {
					if p := recover(); p != nil {
						clear(out)
						panic(ErrInternal)
					}
				}()
				r.opt.onRedact(k, counts[k])
			}()
		}
	}
	if len(out) > 0 {
		defer clear(out)
		if _, err := r.w.Write(out); err != nil {
			return fmt.Errorf("masking: write: %w", err)
		}
	}
	m := copy(r.pending, r.pending[hold:])
	clear(r.pending[m:])
	r.pending = r.pending[:m]
	return nil
}
