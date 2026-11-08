// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package teams formats notify.Event values as Microsoft Teams Adaptive Card
// webhook payloads. It is a pure function: no network access, not wired.
package teams

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/notify"
)

// MaxPayload bounds the encoded message (Teams allows about 28 KB).
const MaxPayload = 20 << 10

// ErrTooLong is returned when the encoded payload exceeds MaxPayload.
var ErrTooLong = errors.New("teams: content exceeds payload limit")

// Escape neutralises Markdown/mention syntax in TextBlock text: markdown
// punctuation is backslash-escaped, angle brackets are entity-encoded (this
// disables <at> mentions) and "@" is followed by a zero-width space.
func Escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '&':
			b.WriteString("&amp;")
		case '\\', '`', '*', '_', '[', ']', '(', ')', '~', '#', '|':
			b.WriteRune('\\')
			b.WriteRune(r)
		case '@':
			b.WriteString("@\u200b")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

type fact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

type element struct {
	Type   string `json:"type"`
	Text   string `json:"text,omitempty"`
	Wrap   bool   `json:"wrap,omitempty"`
	Facts  []fact `json:"facts,omitempty"`
	Weight string `json:"weight,omitempty"`
	Size   string `json:"size,omitempty"`
}

type card struct {
	Schema  string    `json:"$schema"`
	Type    string    `json:"type"`
	Version string    `json:"version"`
	Body    []element `json:"body"`
}

type attachment struct {
	ContentType string `json:"contentType"`
	Content     card   `json:"content"`
}

type message struct {
	Type        string       `json:"type"`
	Attachments []attachment `json:"attachments"`
}

// Format validates ev and returns a Teams webhook message carrying an Adaptive
// Card. It adds no actions or URLs.
func Format(ev notify.Event) ([]byte, error) {
	if err := ev.Validate(); err != nil {
		return nil, err
	}
	summary := Escape(ev.Summary)
	if summary == "" {
		summary = "(no summary)"
	}
	m := message{Type: "message", Attachments: []attachment{{
		ContentType: "application/vnd.microsoft.card.adaptive",
		Content: card{
			Schema: "http://adaptivecards.io/schemas/adaptive-card.json", Type: "AdaptiveCard", Version: "1.4",
			Body: []element{
				{Type: "TextBlock", Text: Escape(ev.Type), Wrap: true, Weight: "Bolder", Size: "Medium"},
				{Type: "TextBlock", Text: summary, Wrap: true},
				{Type: "FactSet", Facts: []fact{
					{Title: "Request", Value: Escape(ev.RequestID)},
					{Title: "Scope", Value: Escape(ev.ScopeID)},
					{Title: "Time", Value: ev.Timestamp.UTC().Format(time.RFC3339)},
				}},
			},
		},
	}}}
	out, err := json.Marshal(m)
	if err != nil {
		return nil, errors.New("teams: encode")
	}
	if len(out) > MaxPayload {
		return nil, ErrTooLong
	}
	return out, nil
}
