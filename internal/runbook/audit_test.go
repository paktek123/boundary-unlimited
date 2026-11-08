// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	testCommit = "0123456789abcdef0123456789abcdef01234567"
	testScript = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func validatedWith(t *testing.T, vals map[string]string) Validated {
	t.Helper()
	var params []Parameter
	for k := range vals {
		params = append(params, Parameter{Name: k, Type: TypeString, Regex: ".*", Required: true})
	}
	sort.Slice(params, func(i, j int) bool { return params[i].Name < params[j].Name })
	c, err := Compile(Definition{
		Name:        "rb",
		Interpreter: InterpreterPosixSh,
		Parameters:  params,
		Selector:    TargetSelector{TargetIDs: []string{"ttcp_1"}},
		Script:      []byte("true"),
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	v, err := c.Validate(vals)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	return v
}

func baseInput(v Validated) EventInput {
	return EventInput{
		Type: EventRunStarted, RunbookId: "rb_1", CommitSHA: testCommit, ScriptSHA256: testScript,
		Params: v, PrincipalId: "u_1", TargetId: "ttcp_1", SessionId: "s_1",
		Outcome: OutcomeNone, Timestamp: time.Unix(1700000000, 0).UTC(), LintPassMarker: true,
	}
}

func TestEventStructHasOnlyAllowedFields(t *testing.T) {
	allowed := map[string]bool{
		"Type": true, "RunbookId": true, "CommitSHA": true, "ScriptSHA256": true, "ParamNames": true,
		"PrincipalId": true, "TargetId": true, "SessionId": true, "Outcome": true, "Timestamp": true,
		"LintPassMarker": true,
	}
	typ := reflect.TypeOf(Event{})
	for i := 0; i < typ.NumField(); i++ {
		if !allowed[typ.Field(i).Name] {
			t.Errorf("unexpected field %q on Event", typ.Field(i).Name)
		}
	}
	if typ.NumField() != len(allowed) {
		t.Errorf("field count %d, want %d", typ.NumField(), len(allowed))
	}
}

func TestCanaryNeverInEvent(t *testing.T) {
	canaries := map[string]string{"SECRET_ONE": "canary-value-Zk39qLw", "TOKEN_TWO": "canary-value-Pq81xNm"}
	v := validatedWith(t, canaries)
	e, err := NewEvent(baseInput(v))
	if err != nil {
		t.Fatal(err)
	}
	if got := e.ParamNames; len(got) != 2 {
		t.Fatalf("names = %v", got)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b) + fmt.Sprintf("%v|%+v|%#v", e, e, e)
	for _, c := range canaries {
		sum := sha256.Sum256([]byte(c))
		for _, bad := range []string{c, hex.EncodeToString(sum[:]), strings.ToUpper(hex.EncodeToString(sum[:]))} {
			if strings.Contains(out, bad) {
				t.Errorf("event output contains a canary or its hash")
			}
		}
	}
	// Errors must not echo input either.
	in := baseInput(v)
	in.PrincipalId = "password=" + canaries["SECRET_ONE"]
	_, err = NewEvent(in)
	if !errors.Is(err, ErrSensitiveField) || strings.Contains(err.Error(), canaries["SECRET_ONE"]) {
		t.Errorf("err = %v", err)
	}
}

func TestNewEventRejects(t *testing.T) {
	v := validatedWith(t, map[string]string{"A": "x"})
	tests := []struct {
		name string
		mut  func(*EventInput)
	}{
		{"bad type", func(i *EventInput) { i.Type = "x" }},
		{"bad outcome", func(i *EventInput) { i.Outcome = "x" }},
		{"finished without outcome", func(i *EventInput) { i.Type = EventRunFinished }},
		{"zero time", func(i *EventInput) { i.Timestamp = time.Time{} }},
		{"empty runbook", func(i *EventInput) { i.RunbookId = "" }},
		{"empty principal", func(i *EventInput) { i.PrincipalId = "" }},
		{"empty target", func(i *EventInput) { i.TargetId = "" }},
		{"control in id", func(i *EventInput) { i.TargetId = "a\nb" }},
		{"long id", func(i *EventInput) { i.RunbookId = strings.Repeat("a", maxIDLen+1) }},
		{"short commit", func(i *EventInput) { i.CommitSHA = "abc" }},
		{"upper commit", func(i *EventInput) { i.CommitSHA = strings.ToUpper(testCommit) }},
		{"bad script hash", func(i *EventInput) { i.ScriptSHA256 = "zz" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := baseInput(v)
			tt.mut(&in)
			if _, err := NewEvent(in); err == nil {
				t.Error("expected error")
			}
		})
	}
	// Optional session id may be empty.
	in := baseInput(v)
	in.SessionId = ""
	if _, err := NewEvent(in); err != nil {
		t.Errorf("empty session: %v", err)
	}
}

func TestRecordingEmitter(t *testing.T) {
	v := validatedWith(t, map[string]string{"A": "x"})
	e, _ := NewEvent(baseInput(v))
	r := &RecordingEmitter{}
	if err := r.Emit(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	got := r.Events()
	got[0].ParamNames[0] = "MUTATED"
	if r.Events()[0].ParamNames[0] != "A" {
		t.Error("recorded event is aliased")
	}
	r2 := &RecordingEmitter{Err: errors.New("boom")}
	if err := r2.Emit(context.Background(), e); err == nil || len(r2.Events()) != 0 {
		t.Error("emit error must propagate and record nothing")
	}
}

// A parameter name at the compile-time cap must still produce an event.
func TestNewEventAcceptsMaxLengthParamName(t *testing.T) {
	name := "A" + strings.Repeat("B", MaxNameLen-1)
	v := validatedWith(t, map[string]string{name: "x"})
	if _, err := NewEvent(baseInput(v)); err != nil {
		t.Errorf("max-length name rejected: %v", err)
	}
}
