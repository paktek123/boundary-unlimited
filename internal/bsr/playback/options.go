// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package playback

import "reflect"

const defaultMaxBytes int64 = 256 << 20

// Option configures Export.
type Option func(*options)

type options struct {
	maxBytes int64
}

func getOpts(opt ...Option) options {
	o := options{maxBytes: defaultMaxBytes}
	for _, f := range opt {
		if f != nil {
			f(&o)
		}
	}
	return o
}

// WithMaxBytes limits the size of converted output that is buffered. Values
// less than one are ignored.
func WithMaxBytes(n int64) Option {
	return func(o *options) {
		if n > 0 {
			o.maxBytes = n
		}
	}
}

// isNil reports whether v is nil or holds a nil pointer, map, func or slice.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Func, reflect.Slice, reflect.Interface, reflect.Chan:
		return rv.IsNil()
	}
	return false
}
