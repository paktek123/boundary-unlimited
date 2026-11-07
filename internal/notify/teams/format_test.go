// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package teams

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/notify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ev() notify.Event {
	return notify.Event{Type: "access_request.created", RequestID: "ar_123", ScopeID: "p_1",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Summary: "please approve"}
}

func TestFormatGolden(t *testing.T) {
	got, err := Format(ev())
	require.NoError(t, err)
	want := `{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"$schema":"http://adaptivecards.io/schemas/adaptive-card.json","type":"AdaptiveCard","version":"1.4","body":[{"type":"TextBlock","text":"access\\_request.created","wrap":true,"weight":"Bolder","size":"Medium"},{"type":"TextBlock","text":"please approve","wrap":true},{"type":"FactSet","facts":[{"title":"Request","value":"ar\\_123"},{"title":"Scope","value":"p\\_1"},{"title":"Time","value":"2026-01-02T03:04:05Z"}]}]}}]}`
	assert.Equal(t, want, string(got))
}

func TestFormatEscapes(t *testing.T) {
	e := ev()
	e.Summary = "<at>everyone</at> [x](http://evil) `c` @here & **b**"
	got, err := Format(e)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(got, &m))
	s := string(got)
	assert.NotContains(t, s, "<at>")
	assert.NotContains(t, s, "[x](")
	assert.NotContains(t, s, "@here")
	assert.Contains(t, s, `\u0026lt;at\u0026gt;`)
}

func TestFormatInvalid(t *testing.T) {
	e := ev()
	e.RequestID = ""
	_, err := Format(e)
	require.ErrorIs(t, err, notify.ErrInvalidEvent)
}

func TestNoActionsOrURLs(t *testing.T) {
	got, err := Format(ev())
	require.NoError(t, err)
	assert.NotContains(t, string(got), "Action.")
}
