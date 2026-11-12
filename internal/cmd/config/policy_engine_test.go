// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func peHCL(body string) string { return "policy_engine {\n" + body + "\n}\n" }

const peBase = `authorizer_id = "opa"
url = "https://pdp.example.com/CANARYPATH"
secret = "env://PDP_SECRET"`

func TestParsePolicyEngine_Valid(t *testing.T) {
	c, err := Parse(peHCL(peBase + "\ntimeout = \"1s\"\ncache_ttl = \"2s\""))
	require.NoError(t, err)
	require.NotNil(t, c.PolicyEngine)
	assert.Equal(t, "opa", c.PolicyEngine.AuthorizerID)
	assert.Equal(t, time.Second, c.PolicyEngine.Timeout)
	assert.Equal(t, 2*time.Second, c.PolicyEngine.CacheTTL)
	assert.NotContains(t, fmt.Sprintf("%v %#v", *c.PolicyEngine, c.PolicyEngine), "CANARYPATH")

	c, err = Parse(`controller { name = "c" }`)
	require.NoError(t, err)
	assert.Nil(t, c.PolicyEngine)
}

func TestParsePolicyEngine_Rejected(t *testing.T) {
	cases := map[string]string{
		"fail_open":      peBase + "\nfail_open = true",
		"skip_verify":    peBase + "\nskip_verify = true",
		"tls option":     peBase + "\ntls_min_version = \"1.0\"",
		"unknown key":    peBase + "\nbogus = 1",
		"http":           "authorizer_id = \"opa\"\nurl = \"http://pdp.example.com/CANARYPATH\"\nsecret = \"env://X\"",
		"userinfo":       "authorizer_id = \"opa\"\nurl = \"https://u:p@pdp.example.com/CANARYPATH\"\nsecret = \"env://X\"",
		"inline secret":  "authorizer_id = \"opa\"\nurl = \"https://pdp.example.com/x\"\nsecret = \"CANARYSECRETVALUE0123456789\"",
		"missing secret": "authorizer_id = \"opa\"\nurl = \"https://pdp.example.com/x\"",
		"missing id":     "url = \"https://pdp.example.com/x\"\nsecret = \"env://X\"",
		"bad timeout":    peBase + "\ntimeout = \"abc\"",
		"timeout high":   peBase + "\ntimeout = \"1h\"",
		"cache high":     peBase + "\ncache_ttl = \"1h\"",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(peHCL(body))
			require.Error(t, err)
			for _, leak := range []string{"CANARYPATH", "CANARYSECRETVALUE", "u:p@"} {
				assert.NotContains(t, err.Error(), leak)
			}
		})
	}
	_, err := Parse(peHCL(peBase) + peHCL(peBase))
	require.Error(t, err, "two blocks")
}
