// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package slack

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/notify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ev() notify.Event {
	return notify.Event{
		Type: "access_request.created", RequestID: "ar_123", ScopeID: "p_1",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Summary: "please approve",
	}
}

func TestFormatGolden(t *testing.T) {
	got, err := Format(ev())
	require.NoError(t, err)
	want := `{"text":"access_request.created","blocks":[{"type":"header","text":{"type":"plain_text","text":"access_request.created"}},{"type":"section","text":{"type":"mrkdwn","text":"please approve"}},{"type":"section","fields":[{"type":"mrkdwn","text":"*Request*\nar_123"},{"type":"mrkdwn","text":"*Scope*\np_1"},{"type":"mrkdwn","text":"*Type*\naccess_request.created"}]},{"type":"context","elements":[{"type":"mrkdwn","text":"2026-01-02T03:04:05Z"}]}]}`
	assert.Equal(t, want, string(got))
	assert.True(t, json.Valid(got))
}

func TestFormatEscapesInjection(t *testing.T) {
	e := ev()
	e.Summary = "<!here> <!channel> <@U123> & `code` *b* @channel <https://evil|click>"
	got, err := Format(e)
	require.NoError(t, err)
	var p payload
	require.NoError(t, json.Unmarshal(got, &p))
	s := p.Blocks[1].Text.Text
	for _, bad := range []string{"<", ">", "`", "@channel"} {
		assert.NotContains(t, s, bad)
	}
	assert.Contains(t, s, "&lt;!here&gt;")
	assert.Contains(t, s, "&amp;")
}

func TestFormatRejects(t *testing.T) {
	bad := ev()
	bad.Type = ""
	_, err := Format(bad)
	require.ErrorIs(t, err, notify.ErrInvalidEvent)

	// Worst-case escaping expansion (512 x "&" -> 5 bytes each) must still
	// fit the section limit, so ErrTooLong is unreachable for valid events.
	big := ev()
	big.Summary = strings.Repeat("&", notify.MaxSummaryLen)
	out, err := Format(big)
	require.NoError(t, err)
	assert.Less(t, len(out), MaxPayload)
}

func TestFormatNoSecretsOrURLs(t *testing.T) {
	got, err := Format(ev())
	require.NoError(t, err)
	assert.NotContains(t, string(got), "http")
	assert.NotContains(t, string(got), `"button"`)
}
