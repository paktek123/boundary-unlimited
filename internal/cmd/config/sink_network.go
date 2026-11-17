// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/hcl/ast"
)

var networkSinkKeys = map[string]map[string]bool{
	"http": {
		"url": true, "token": true, "format": true,
		"allow_private_cidrs": true, "delivery_guarantee": true,
	},
	"syslog": {
		"network": true, "address": true, "insecure_plaintext": true,
		"ca_file": true, "client_cert_file": true, "client_key_file": true,
		"allow_private_cidrs": true, "delivery_guarantee": true,
	},
}

// rejectUnknownNetworkSinkKeys fails the load when an `http` or `syslog` block
// inside an event sink carries a key that is not enforced (so options such as
// skip_verify cannot be set). Errors name keys only, never values.
func rejectUnknownNetworkSinkKeys(sink ast.Node) error {
	obj, ok := sink.(*ast.ObjectType)
	if !ok {
		return nil
	}
	for block, allowed := range networkSinkKeys {
		for _, item := range obj.List.Filter(block).Items {
			inner, ok := item.Val.(*ast.ObjectType)
			if !ok {
				continue
			}
			var unknown []string
			for _, kv := range inner.List.Items {
				k := "?"
				if len(kv.Keys) > 0 {
					k = fmt.Sprint(kv.Keys[0].Token.Value())
				}
				if len(kv.Keys) != 1 || !allowed[k] {
					unknown = append(unknown, k)
				}
			}
			if len(unknown) > 0 {
				sort.Strings(unknown)
				return fmt.Errorf("sink %q block: unknown or unsupported keys %v", block, unknown)
			}
		}
	}
	return nil
}
