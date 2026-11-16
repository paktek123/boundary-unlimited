// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/boundary/internal/policyhook"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

// policyEngineKeys are the only accepted keys. There is deliberately no
// fail_open, skip_verify or TLS option.
var policyEngineKeys = map[string]bool{
	"authorizer_id": true, "url": true, "secret": true, "timeout": true, "cache_ttl": true,
}

// parsePolicyEngine parses the optional `policy_engine { ... }` block. Errors
// never contain the url or the secret reference.
func parsePolicyEngine(root *ast.ObjectList) (*policyhook.EngineConfig, error) {
	items := root.Filter("policy_engine").Items
	switch len(items) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, fmt.Errorf("too many policy_engine blocks (max 1, got %d)", len(items))
	}
	obj, ok := items[0].Val.(*ast.ObjectType)
	if !ok {
		return nil, fmt.Errorf("policy_engine is not a block")
	}
	var unknown []string
	for _, kv := range obj.List.Items {
		k := "?"
		if len(kv.Keys) > 0 {
			k = fmt.Sprint(kv.Keys[0].Token.Value())
		}
		if len(kv.Keys) != 1 || !policyEngineKeys[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("policy_engine: unknown or unsupported keys %v", unknown)
	}
	var raw struct {
		AuthorizerID string `hcl:"authorizer_id"`
		URL          string `hcl:"url"`
		Secret       string `hcl:"secret"`
		Timeout      string `hcl:"timeout"`
		CacheTTL     string `hcl:"cache_ttl"`
	}
	if err := hcl.DecodeObject(&raw, items[0].Val); err != nil {
		return nil, fmt.Errorf("policy_engine: invalid block")
	}
	cfg := &policyhook.EngineConfig{AuthorizerID: raw.AuthorizerID, URL: raw.URL, SecretRef: raw.Secret}
	var err error
	if raw.Timeout != "" {
		if cfg.Timeout, err = time.ParseDuration(raw.Timeout); err != nil {
			return nil, fmt.Errorf("policy_engine: timeout is not a duration")
		}
	}
	if raw.CacheTTL != "" {
		if cfg.CacheTTL, err = time.ParseDuration(raw.CacheTTL); err != nil {
			return nil, fmt.Errorf("policy_engine: cache_ttl is not a duration")
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}
