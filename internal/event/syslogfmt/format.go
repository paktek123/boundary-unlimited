// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package syslogfmt is a pure RFC 5424 message formatter for event sinks. It
// opens no sockets and reads no configuration; nothing in the event system
// uses it yet.
//
// Header fields are validated and rejected when invalid (never silently
// truncated). Free text (MSG and structured-data values) is escaped so that a
// single event can never produce a second log line.
package syslogfmt

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits. Frames larger than the cap are rejected with ErrFrameTooLarge.
const (
	MaxHostnameLen = 255
	MaxAppNameLen  = 48
	MaxProcIDLen   = 128
	MaxMsgIDLen    = 32
	MaxSDNameLen   = 32

	// MaxFrameSize is the largest accepted frame (stream transports).
	MaxFrameSize = 64 * 1024
	// MaxDatagramSize is the largest accepted frame for UDP.
	MaxDatagramSize = 2048
)

// Errors. Messages never echo field values.
var (
	ErrInvalidField  = errors.New("syslogfmt: invalid field")
	ErrFrameTooLarge = errors.New("syslogfmt: frame exceeds the maximum size")
)

// Severity is an RFC 5424 severity (0-7).
type Severity int

// Severities.
const (
	SevEmergency Severity = iota
	SevAlert
	SevCritical
	SevError
	SevWarning
	SevNotice
	SevInfo
	SevDebug
)

// Facility is an RFC 5424 facility (0-23).
type Facility int

// FacilityLocal0 is a sensible default for application events.
const FacilityLocal0 Facility = 16

// Kind is a Boundary event type.
type Kind string

// Event kinds.
const (
	KindAudit       Kind = "audit"
	KindObservation Kind = "observation"
	KindError       Kind = "error"
	KindSystem      Kind = "system"
)

// SeverityFor maps a Boundary event kind to a syslog severity. Unknown kinds
// map to SevWarning so they are never silently demoted.
func SeverityFor(k Kind) Severity {
	switch k {
	case KindError:
		return SevError
	case KindAudit:
		return SevNotice
	case KindSystem, KindObservation:
		return SevInfo
	default:
		return SevWarning
	}
}

// SDParam is one structured-data parameter.
type SDParam struct {
	Name  string
	Value string
}

// SDElement is one structured-data element.
type SDElement struct {
	ID     string
	Params []SDParam
}

// Message is the input to Format. Empty header strings become the NILVALUE.
// Severity's zero value is SevEmergency: always set it explicitly. A wholly
// zero Message is rejected.
type Message struct {
	Facility  Facility
	Severity  Severity
	Timestamp time.Time // zero means NILVALUE
	Hostname  string
	AppName   string
	ProcID    string
	MsgID     string
	SD        []SDElement
	Msg       string
}

func printableASCII(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

func nilable(s string, max int) (string, error) {
	if s == "" {
		return "-", nil
	}
	if !printableASCII(s, max) {
		return "", ErrInvalidField
	}
	return s, nil
}

func validSDName(s string) bool {
	if s == "" || !printableASCII(s, MaxSDNameLen) {
		return false
	}
	return !strings.ContainsAny(s, "= ]\"")
}

// escape makes free text safe: backslash, control characters, DEL, C1 controls
// and Unicode line/paragraph separators are written as visible escapes, and
// invalid UTF-8 becomes U+FFFD. extra lists additional bytes to backslash.
func escape(s string, extra string) string {
	var sb strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			sb.WriteRune(utf8.RuneError)
		case r == '\\' || (r < 0x80 && strings.ContainsRune(extra, r)):
			sb.WriteByte('\\')
			sb.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&sb, "\\x%02x", r)
		case (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			fmt.Fprintf(&sb, "\\u%04x", r)
		default:
			sb.WriteRune(r)
		}
		i += n
	}
	return sb.String()
}

// Format returns the RFC 5424 frame for msg with no transport framing.
func Format(msg Message) ([]byte, error) {
	return format(msg, MaxFrameSize)
}

// FormatDatagram returns a UDP-ready frame: newline-free and at most
// MaxDatagramSize bytes.
func FormatDatagram(msg Message) ([]byte, error) {
	return format(msg, MaxDatagramSize)
}

// FormatOctetCounted returns the RFC 6587 octet-counting frame for TCP/TLS:
// "<len> <frame>".
func FormatOctetCounted(msg Message) ([]byte, error) {
	b, err := format(msg, MaxFrameSize)
	if err != nil {
		return nil, err
	}
	return append([]byte(strconv.Itoa(len(b))+" "), b...), nil
}

func format(msg Message, maxSize int) ([]byte, error) {
	// The zero Severity is emergency (0); a wholly zero Message is almost
	// certainly a forgotten field, so reject it rather than emit kern.emerg.
	if msg.Facility == 0 && msg.Severity == 0 && msg.Timestamp.IsZero() && msg.Hostname == "" &&
		msg.AppName == "" && msg.ProcID == "" && msg.MsgID == "" && len(msg.SD) == 0 && msg.Msg == "" {
		return nil, ErrInvalidField
	}
	if msg.Facility < 0 || msg.Facility > 23 || msg.Severity < 0 || msg.Severity > 7 {
		return nil, ErrInvalidField
	}
	host, err := nilable(msg.Hostname, MaxHostnameLen)
	if err != nil {
		return nil, err
	}
	app, err := nilable(msg.AppName, MaxAppNameLen)
	if err != nil {
		return nil, err
	}
	proc, err := nilable(msg.ProcID, MaxProcIDLen)
	if err != nil {
		return nil, err
	}
	mid, err := nilable(msg.MsgID, MaxMsgIDLen)
	if err != nil {
		return nil, err
	}
	ts := "-"
	if !msg.Timestamp.IsZero() {
		ts = msg.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z07:00")
	}

	var sb strings.Builder
	sb.WriteString("<" + strconv.Itoa(int(msg.Facility)*8+int(msg.Severity)) + ">1 ")
	sb.WriteString(ts + " " + host + " " + app + " " + proc + " " + mid + " ")
	if len(msg.SD) == 0 {
		sb.WriteString("-")
	}
	seen := map[string]struct{}{}
	for _, el := range msg.SD {
		if !validSDName(el.ID) {
			return nil, ErrInvalidField
		}
		if _, dup := seen[el.ID]; dup {
			return nil, ErrInvalidField
		}
		seen[el.ID] = struct{}{}
		sb.WriteString("[" + el.ID)
		for _, p := range el.Params {
			if !validSDName(p.Name) {
				return nil, ErrInvalidField
			}
			sb.WriteString(" " + p.Name + "=\"" + escape(p.Value, "\"]") + "\"")
		}
		sb.WriteString("]")
	}
	if msg.Msg != "" {
		sb.WriteString(" " + escape(msg.Msg, ""))
	}
	if sb.Len() > maxSize {
		return nil, ErrFrameTooLarge
	}
	return []byte(sb.String()), nil
}
