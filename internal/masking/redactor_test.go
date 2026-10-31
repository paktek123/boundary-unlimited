// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package masking

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fake values for tests only (documented example/test numbers).
const (
	testCard = "4111 1111 1111 1111"
	testAWS  = "AKIAIOSFODNN7EXAMPLE"
	testJWT  = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"
	testPEM  = "-----BEGIN PRIVATE KEY-----\nZmFrZWtleWZha2VrZXk=\n-----END PRIVATE KEY-----"
)

func redactAll(t *testing.T, in string, opt ...Option) string {
	t.Helper()
	var buf bytes.Buffer
	r, err := New(&buf, opt...)
	require.NoError(t, err)
	_, err = r.Write([]byte(in))
	require.NoError(t, err)
	require.NoError(t, r.Close())
	return buf.String()
}

func TestDetectors(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"card spaces", "pay " + testCard + " now", "pay [REDACTED:credit_card] now"},
		{"card plain", "4111111111111111", "[REDACTED:credit_card]"},
		{"card dashes", "4111-1111-1111-1111.", "[REDACTED:credit_card]."},
		{"non-luhn digits", "1234567890123456", "1234567890123456"},
		{"too short", "411111111111", "411111111111"},
		{"too long run", "41111111111111111111", "41111111111111111111"},
		{"email", "mail bob.smith+x@example.co.uk please", "mail [REDACTED:email] please"},
		{"not email", "a @ b and user@localhost", "a @ b and user@localhost"},
		{"aws", "key=" + testAWS + ";", "key=[REDACTED:aws_access_key];"},
		{"aws wrong prefix", "AKXXIOSFODNN7EXAMPLE", "AKXXIOSFODNN7EXAMPLE"},
		{"jwt", "Bearer " + testJWT + " ok", "Bearer [REDACTED:jwt] ok"},
		{"pem", "before\n" + testPEM + "\nafter", "before\n[REDACTED:private_key]\nafter"},
		{"plain text", "hello world, nothing to see", "hello world, nothing to see"},
		{"multiple", testAWS + " " + testCard, "[REDACTED:aws_access_key] [REDACTED:credit_card]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, redactAll(t, tc.in))
		})
	}
}

func TestSplitAtEveryOffset(t *testing.T) {
	for _, secret := range []struct{ name, s, token string }{
		{"card", testCard, "[REDACTED:credit_card]"},
		{"email", "alice@example.com", "[REDACTED:email]"},
		{"aws", testAWS, "[REDACTED:aws_access_key]"},
		{"jwt", testJWT, "[REDACTED:jwt]"},
		{"pem", testPEM, "[REDACTED:private_key]"},
	} {
		in := "prefix " + secret.s + " suffix"
		want := "prefix " + secret.token + " suffix"
		for _, maxLen := range []int{DefaultMaxPatternLen, 128} {
			for i := 0; i <= len(in); i++ {
				var buf bytes.Buffer
				r, err := New(&buf, WithMaxPatternLen(maxLen))
				require.NoError(t, err)
				_, err = r.Write([]byte(in[:i]))
				require.NoError(t, err)
				_, err = r.Write([]byte(in[i:]))
				require.NoError(t, err)
				require.NoError(t, r.Close())
				require.Equal(t, want, buf.String(), "%s maxLen=%d split=%d", secret.name, maxLen, i)
			}
		}
	}
}

func TestByteAtATime(t *testing.T) {
	in := "x " + testAWS + " y " + testJWT + " z " + testPEM + " end"
	var buf bytes.Buffer
	r, err := New(&buf, WithMaxPatternLen(256))
	require.NoError(t, err)
	for i := 0; i < len(in); i++ {
		_, err := r.Write([]byte{in[i]})
		require.NoError(t, err)
	}
	require.NoError(t, r.Close())
	assert.Equal(t, "x [REDACTED:aws_access_key] y [REDACTED:jwt] z [REDACTED:private_key] end", buf.String())
}

func TestUnterminatedPEMRedactedAtClose(t *testing.T) {
	got := redactAll(t, "a\n-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n")
	assert.Equal(t, "a\n[REDACTED:private_key]", got)
	assert.NotContains(t, got, "ZmFrZQ")
}

func TestPEMNeverLeaksBeforeEnd(t *testing.T) {
	var buf bytes.Buffer
	r, err := New(&buf, WithMaxPatternLen(1024))
	require.NoError(t, err)
	_, err = r.Write([]byte("-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("A", 500)))
	require.NoError(t, err)
	_, err = r.Write([]byte(strings.Repeat("B", 400)))
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "BEGIN")
	assert.NotContains(t, buf.String(), "AAAA")
}

func TestBufferLimitFailsClosed(t *testing.T) {
	var buf bytes.Buffer
	r, err := New(&buf, WithMaxPatternLen(64))
	require.NoError(t, err)
	_, err = r.Write([]byte("-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("A", 200)))
	require.ErrorIs(t, err, ErrBufferLimit)
	assert.Empty(t, buf.String(), "nothing unredacted is written")
	_, err = r.Write([]byte("more"))
	require.ErrorIs(t, err, ErrBufferLimit)
	require.ErrorIs(t, r.Close(), ErrBufferLimit)
	assert.Empty(t, buf.String())
}

func TestMatchLongerThanLimit(t *testing.T) {
	var buf bytes.Buffer
	r, err := New(&buf, WithMaxPatternLen(16))
	require.NoError(t, err)
	_, err = r.Write([]byte("x " + testJWT + " y"))
	require.ErrorIs(t, err, ErrBufferLimit)
	assert.NotContains(t, buf.String(), "eyJ")
}

type panicDetector struct{}

func (panicDetector) Name() string       { return "boom" }
func (panicDetector) Find([]byte) []Span { panic("boom") }

type badSpanDetector struct{}

func (badSpanDetector) Name() string       { return "bad" }
func (badSpanDetector) Find([]byte) []Span { return []Span{{5, 1000}} }

func TestDetectorFailureFailsClosed(t *testing.T) {
	for name, d := range map[string]Detector{"panic": panicDetector{}, "badspan": badSpanDetector{}} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			r, err := New(&buf, WithDetectors(d))
			require.NoError(t, err)
			_, err = r.Write([]byte("secret stuff here"))
			require.Error(t, err)
			assert.Empty(t, buf.String())
			require.Error(t, r.Close())
			assert.Empty(t, buf.String())
		})
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestUnderlyingWriteError(t *testing.T) {
	r, err := New(failWriter{}, WithMaxPatternLen(4))
	require.NoError(t, err)
	_, err = r.Write([]byte("plenty of plain text"))
	require.ErrorContains(t, err, "disk full")
	_, err = r.Write([]byte("x"))
	require.Error(t, err)
}

func TestCloseFlushesHeldBytesAndRejectsWrites(t *testing.T) {
	var buf bytes.Buffer
	r, err := New(&buf)
	require.NoError(t, err)
	n, err := r.Write([]byte("short"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Empty(t, buf.String(), "held until close")
	require.NoError(t, r.Flush())
	assert.Equal(t, "short", buf.String())
	require.NoError(t, r.Close(), "close is idempotent")
	_, err = r.Write([]byte("x"))
	require.ErrorIs(t, err, ErrClosed)
}

func TestOptionsAndCustomDetector(t *testing.T) {
	d, err := NewRegexDetector("ticket", `TKT-[0-9]{4}`)
	require.NoError(t, err)
	got := redactAll(t, "see TKT-1234 and "+testAWS, WithDetectors(d), WithReplacement("<{detector}>"))
	assert.Equal(t, "see <ticket> and "+testAWS, got)

	_, err = NewRegexDetector("", "x")
	require.Error(t, err)
	_, err = NewRegexDetector("bad", "(")
	require.Error(t, err)
	_, err = NewRegexDetector("empty", "a*")
	require.Error(t, err)

	_, err = New(nil)
	require.Error(t, err)
	_, err = New(&bytes.Buffer{}, WithMaxPatternLen(0))
	require.Error(t, err)
	_, err = New(&bytes.Buffer{}, WithDetectors(nil))
	require.Error(t, err)
}

func TestLuhn(t *testing.T) {
	assert.True(t, luhnValid([]byte("4111111111111111")))
	assert.True(t, luhnValid([]byte("5500-0000-0000-0004")))
	assert.False(t, luhnValid([]byte("4111111111111112")))
	assert.False(t, luhnValid([]byte("411111111111")))
	assert.False(t, luhnValid([]byte("41x1111111111111")))
}

func mixed(size int) []byte {
	unit := "GET /index.html 200 OK user=guest id=1234567890123456 note=plain text line\n" +
		"contact bob@example.com key " + testAWS + " card " + testCard + "\n"
	return []byte(strings.Repeat(unit, size/len(unit)+1)[:size])
}

func BenchmarkRedactor1MiB(b *testing.B) {
	data := mixed(1 << 20)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r, _ := New(&bytes.Buffer{})
		for off := 0; off < len(data); off += 4096 {
			end := off + 4096
			if end > len(data) {
				end = len(data)
			}
			if _, err := r.Write(data[off:end]); err != nil {
				b.Fatal(err)
			}
		}
		if err := r.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
