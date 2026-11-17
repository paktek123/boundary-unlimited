// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"fmt"
)

const (
	StderrSink SinkType = "stderr" // StderrSink is written to stderr
	FileSink   SinkType = "file"   // FileSink is written to a file
	WriterSink SinkType = "writer" // WriterSink is written to an io.Writer
	HTTPSink   SinkType = "http"   // HTTPSink streams to an https collector (not yet supported)
	SyslogSink SinkType = "syslog" // SyslogSink streams RFC 5424 to a collector (not yet supported)
)

type SinkType string // SinkType defines the type of sink in a config stanza (file, stderr, writer)

func (t SinkType) Validate() error {
	const op = "event.(SinkType).validate"
	switch t {
	case StderrSink, FileSink, WriterSink, HTTPSink, SyslogSink:
		return nil
	default:
		return fmt.Errorf("%s: '%s' is not a valid sink type: %w", op, t, ErrInvalidParameter)
	}
}
