// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package slack formats notify.Event values as Slack incoming-webhook Block
// Kit payloads. It is a pure function: no network access and no wiring.
package slack

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/notify"
)

// Slack block limits (header text 150, section text 3000, field text 2000).
// Inputs that would exceed them are rejected, never truncated.
const (
	MaxHeaderLen  = 150
	MaxSectionLen = 3000
	MaxPayload    = 16 << 10
)

// ErrTooLong is returned when escaped content exceeds a Slack block limit.
var ErrTooLong = errors.New("slack: content exceeds block limit")

type text struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type block struct {
	Type     string `json:"type"`
	Text     *text  `json:"text,omitempty"`
	Fields   []text `json:"fields,omitempty"`
	Elements []text `json:"elements,omitempty"`
}

type payload struct {
	Text   string  `json:"text"`
	Blocks []block `json:"blocks"`
}

// Escape neutralises Slack mrkdwn control characters. Ampersand and angle
// brackets are entity-encoded (which also disables <!here>, <!channel> and
// <@U..> mentions and links); backticks are replaced and the at sign is followed by a
// zero-width space so user text cannot open code spans or ping. Slack has no
// escape for *, _ and ~, so those can only cause cosmetic formatting.
func Escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '`':
			b.WriteString("'")
		case '@':
			b.WriteString("@\u200b")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func md(s string) text { return text{Type: "mrkdwn", Text: s} }

// Format validates ev and returns a Slack incoming-webhook JSON payload. It
// adds no buttons or callback URLs.
func Format(ev notify.Event) ([]byte, error) {
	if err := ev.Validate(); err != nil {
		return nil, err
	}
	// plain_text headers are not mrkdwn; use the validated type verbatim.
	header := ev.Type
	if len(header) > MaxHeaderLen {
		return nil, ErrTooLong
	}
	summary := Escape(ev.Summary)
	if summary == "" {
		summary = "(no summary)"
	}
	if len(summary) > MaxSectionLen {
		return nil, ErrTooLong
	}
	fields := []text{
		md("*Request*\n" + Escape(ev.RequestID)),
		md("*Scope*\n" + Escape(ev.ScopeID)),
		md("*Type*\n" + Escape(ev.Type)),
	}
	for _, f := range fields {
		if len(f.Text) > 2000 {
			return nil, ErrTooLong
		}
	}
	p := payload{
		Text: header,
		Blocks: []block{
			{Type: "header", Text: &text{Type: "plain_text", Text: header}},
			{Type: "section", Text: &text{Type: "mrkdwn", Text: summary}},
			{Type: "section", Fields: fields},
			{Type: "context", Elements: []text{md(ev.Timestamp.UTC().Format(time.RFC3339))}},
		},
	}
	out, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("slack: encode")
	}
	if len(out) > MaxPayload {
		return nil, ErrTooLong
	}
	return out, nil
}
