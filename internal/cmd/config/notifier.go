// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"sort"

	"github.com/hashicorp/boundary/internal/notify/sender"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

// notifierKeys are the only keys a notifier block accepts. There is no TLS
// option at all: every sender uses the guarded https dialer.
var notifierKeys = map[string]bool{"type": true, "url": true, "secret": true}

// parseNotifiers parses the `notifier "<name>" { type, url, secret }` blocks.
// Unknown keys fail the load (so skip_verify or TLS options cannot be set).
// Errors never contain the url or secret values.
func parseNotifiers(root *ast.ObjectList) ([]sender.Destination, error) {
	var out []sender.Destination
	for _, item := range root.Filter("notifier").Items {
		if len(item.Keys) != 1 {
			return nil, fmt.Errorf(`"notifier" blocks need exactly one label: notifier "<name>" { ... }`)
		}
		name := fmt.Sprint(item.Keys[0].Token.Value())
		obj, ok := item.Val.(*ast.ObjectType)
		if !ok {
			return nil, fmt.Errorf(`notifier %q is not a block`, name)
		}
		var unknown []string
		for _, kv := range obj.List.Items {
			k := "?"
			if len(kv.Keys) > 0 {
				k = fmt.Sprint(kv.Keys[0].Token.Value())
			}
			if len(kv.Keys) != 1 || !notifierKeys[k] {
				unknown = append(unknown, k)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return nil, fmt.Errorf("notifier %q: unknown or unsupported keys %v", name, unknown)
		}
		var raw struct {
			Type   string `hcl:"type"`
			URL    string `hcl:"url"`
			Secret string `hcl:"secret"`
		}
		if err := hcl.DecodeObject(&raw, item.Val); err != nil {
			return nil, fmt.Errorf("notifier %q: invalid block", name)
		}
		d := sender.Destination{Name: name, Type: raw.Type, URL: raw.URL, SecretRef: raw.Secret}
		if err := d.Validate(); err != nil {
			return nil, err
		}
		for _, p := range out {
			if p.Name == d.Name {
				return nil, fmt.Errorf("duplicate notifier %q", d.Name)
			}
		}
		out = append(out, d)
	}
	return out, nil
}
