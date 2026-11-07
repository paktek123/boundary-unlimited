// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package syslogfmt_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/event/syslogfmt"
	"github.com/stretchr/testify/require"
)

var ts = time.Date(2026, 11, 7, 12, 30, 45, 123456789, time.UTC)

func base() syslogfmt.Message {
	return syslogfmt.Message{
		Facility: syslogfmt.FacilityLocal0, Severity: syslogfmt.SevNotice, Timestamp: ts,
		Hostname: "host1", AppName: "boundary", ProcID: "42", MsgID: "audit",
		SD:  []syslogfmt.SDElement{{ID: "meta@32473", Params: []syslogfmt.SDParam{{Name: "k", Value: "v"}}}},
		Msg: "hello",
	}
}

func TestGolden(t *testing.T) {
	b, err := syslogfmt.Format(base())
	require.NoError(t, err)
	require.Equal(t, `<133>1 2026-11-07T12:30:45.123456Z host1 boundary 42 audit [meta@32473 k="v"] hello`, string(b))

	b, err = syslogfmt.Format(syslogfmt.Message{Facility: 1, Severity: 6})
	require.NoError(t, err)
	require.Equal(t, `<14>1 - - - - - -`, string(b))

	b, err = syslogfmt.FormatOctetCounted(base())
	require.NoError(t, err)
	require.Equal(t, `83 <133>1 2026-11-07T12:30:45.123456Z host1 boundary 42 audit [meta@32473 k="v"] hello`, string(b))

	b, err = syslogfmt.FormatDatagram(base())
	require.NoError(t, err)
	require.NotContains(t, string(b), "\n")
}

func TestSeverityFor(t *testing.T) {
	require.Equal(t, syslogfmt.SevError, syslogfmt.SeverityFor(syslogfmt.KindError))
	require.Equal(t, syslogfmt.SevNotice, syslogfmt.SeverityFor(syslogfmt.KindAudit))
	require.Equal(t, syslogfmt.SevInfo, syslogfmt.SeverityFor(syslogfmt.KindObservation))
	require.Equal(t, syslogfmt.SevInfo, syslogfmt.SeverityFor(syslogfmt.KindSystem))
	require.Equal(t, syslogfmt.SevWarning, syslogfmt.SeverityFor("weird"))
}

func TestRejectsInvalidHeaders(t *testing.T) {
	mut := map[string]func(*syslogfmt.Message){
		"facility":      func(m *syslogfmt.Message) { m.Facility = 24 },
		"neg severity":  func(m *syslogfmt.Message) { m.Severity = -1 },
		"host space":    func(m *syslogfmt.Message) { m.Hostname = "a b" },
		"host nonascii": func(m *syslogfmt.Message) { m.Hostname = "hôst" },
		"host long":     func(m *syslogfmt.Message) { m.Hostname = strings.Repeat("a", 256) },
		"app long":      func(m *syslogfmt.Message) { m.AppName = strings.Repeat("a", 49) },
		"proc newline":  func(m *syslogfmt.Message) { m.ProcID = "1\n2" },
		"msgid long":    func(m *syslogfmt.Message) { m.MsgID = strings.Repeat("a", 33) },
		"sd id bad":     func(m *syslogfmt.Message) { m.SD[0].ID = "a]b" },
		"sd id empty":   func(m *syslogfmt.Message) { m.SD[0].ID = "" },
		"sd param bad":  func(m *syslogfmt.Message) { m.SD[0].Params[0].Name = "a=b" },
		"sd dup":        func(m *syslogfmt.Message) { m.SD = append(m.SD, m.SD[0]) },
	}
	for name, f := range mut {
		t.Run(name, func(t *testing.T) {
			m := base()
			m.SD = append([]syslogfmt.SDElement(nil), m.SD...)
			m.SD[0].Params = append([]syslogfmt.SDParam(nil), m.SD[0].Params...)
			f(&m)
			_, err := syslogfmt.Format(m)
			require.ErrorIs(t, err, syslogfmt.ErrInvalidField)
		})
	}
}

func TestSDValueEscaping(t *testing.T) {
	m := base()
	m.SD[0].Params[0].Value = `a"b\c]d` + "\n"
	b, err := syslogfmt.Format(m)
	require.NoError(t, err)
	require.Contains(t, string(b), `k="a\"b\\c\]d\x0a"`)
}

func TestMsgInjection(t *testing.T) {
	m := base()
	m.Msg = "ok\n<134>1 2026-01-01T00:00:00Z evil app 1 x - forged\r\x00\x1b[2J \u0085end\xff"
	for _, f := range []func(syslogfmt.Message) ([]byte, error){syslogfmt.Format, syslogfmt.FormatDatagram, syslogfmt.FormatOctetCounted} {
		b, err := f(m)
		require.NoError(t, err)
		s := string(b)
		for _, bad := range []string{"\n", "\r", "\x00", "\x1b", " ", "\u0085", "\xff"} {
			require.NotContains(t, s, bad)
		}
	}
}

func TestSizeCaps(t *testing.T) {
	m := base()
	m.Msg = strings.Repeat("a", syslogfmt.MaxDatagramSize)
	_, err := syslogfmt.FormatDatagram(m)
	require.ErrorIs(t, err, syslogfmt.ErrFrameTooLarge)
	_, err = syslogfmt.Format(m)
	require.NoError(t, err)
	m.Msg = strings.Repeat("a", syslogfmt.MaxFrameSize)
	_, err = syslogfmt.Format(m)
	require.ErrorIs(t, err, syslogfmt.ErrFrameTooLarge)
	_, err = syslogfmt.FormatOctetCounted(m)
	require.ErrorIs(t, err, syslogfmt.ErrFrameTooLarge)
}

func FuzzFormat(f *testing.F) {
	f.Add("host", "app", "1", "id", "sd", "k", "v", "msg", 16, 5)
	f.Fuzz(func(t *testing.T, host, app, proc, mid, sdid, pn, pv, msg string, fac, sev int) {
		m := syslogfmt.Message{
			Facility: syslogfmt.Facility(fac), Severity: syslogfmt.Severity(sev), Timestamp: ts,
			Hostname: host, AppName: app, ProcID: proc, MsgID: mid, Msg: msg,
			SD: []syslogfmt.SDElement{{ID: sdid, Params: []syslogfmt.SDParam{{Name: pn, Value: pv}}}},
		}
		b, err := syslogfmt.FormatDatagram(m)
		if err == nil {
			if strings.ContainsAny(string(b), "\n\r") {
				t.Fatal("newline in frame")
			}
		}
	})
}
