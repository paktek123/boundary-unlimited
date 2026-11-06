// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package runbook

import (
	"bytes"
	"encoding/json"
	"errors"
)

// ParamType is the type of a runbook parameter.
type ParamType string

// Parameter types.
const (
	TypeString ParamType = "string"
	TypeInt    ParamType = "int"
	TypeEnum   ParamType = "enum"
	TypeBool   ParamType = "bool"
)

// Parameter declares one runbook parameter.
type Parameter struct {
	Name string    `json:"name"`
	Type ParamType `json:"type"`
	// Regex is an RE2 expression a string value must match in full. It is
	// mandatory for TypeString.
	Regex string `json:"regex,omitempty"`
	// AllowedValues is the mandatory value list for TypeEnum.
	AllowedValues []string `json:"allowed_values,omitempty"`
	// Min and Max bound a TypeInt value; both are mandatory for TypeInt.
	Min *int64 `json:"min,omitempty"`
	Max *int64 `json:"max,omitempty"`
	// MaxLength bounds the value in bytes. Zero means DefaultMaxLength.
	MaxLength  int    `json:"max_length,omitempty"`
	Required   bool   `json:"required,omitempty"`
	Default    string `json:"default,omitempty"`
	HasDefault bool   `json:"has_default,omitempty"`
}

// TargetSelector says which targets a runbook may run against. The zero value
// selects nothing: a runbook applies to every target only if AllTargets is set
// explicitly.
type TargetSelector struct {
	AllTargets bool     `json:"all_targets,omitempty"`
	TargetIDs  []string `json:"target_ids,omitempty"`
	ScopeIDs   []string `json:"scope_ids,omitempty"`
}

// Definition is a runbook definition.
type Definition struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Selector    TargetSelector `json:"selector"`
	Interpreter string         `json:"interpreter"`
	Parameters  []Parameter    `json:"parameters,omitempty"`
	Script      []byte         `json:"script"`
}

// DecodeDefinition strictly decodes a JSON definition: unknown fields and
// trailing data are rejected. The error never echoes the input.
func DecodeDefinition(b []byte) (Definition, error) {
	var d Definition
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Definition{}, errors.New("runbook: invalid definition encoding")
	}
	if dec.More() {
		return Definition{}, errors.New("runbook: trailing data after definition")
	}
	return d, nil
}
