// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func eventsHCL(sink string) string {
	return `controller { name = "c" }
events {
  sink {
    name = "siem"
    event_types = ["audit"]
    format = "cloudevents-json"
` + sink + `
  }
}`
}

func TestParse_NetworkSinks(t *testing.T) {
	valid := map[string]string{
		"http": `type = "http"
http { url = "https://siem.example.com/CANARYPATH"
 token = "env://SIEM_TOKEN"
 format = "hec" }`,
		"syslog": `type = "syslog"
syslog { address = "logs.example.com:6514" }`,
	}
	for name, sink := range valid {
		t.Run("valid is not yet supported "+name, func(t *testing.T) {
			_, err := Parse(eventsHCL(sink))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not yet supported")
			assert.NotContains(t, err.Error(), "CANARYPATH")
		})
	}
	invalid := map[string]string{
		"http scheme": `type = "http"
http { url = "http://siem.example.com/CANARYPATH"
 token = "env://T"
 format = "hec" }`,
		"inline token": `type = "http"
http { url = "https://siem.example.com/CANARYPATH"
 token = "CANARYSECRET0123456789"
 format = "hec" }`,
		"unknown key skip_verify": `type = "http"
http { url = "https://siem.example.com/CANARYPATH"
 token = "env://T"
 format = "hec"
 skip_verify = true }`,
		"unknown syslog key": `type = "syslog"
syslog { address = "logs.example.com:6514"
 tls_min_version = "1.0" }`,
		"plaintext syslog": `type = "syslog"
syslog { network = "tcp"
 address = "logs.example.com:514" }`,
		"wildcard cidr": `type = "http"
http { url = "https://siem.example.com/CANARYPATH"
 token = "env://T"
 format = "json"
 allow_private_cidrs = ["0.0.0.0/0"] }`,
		"enforced": `type = "http"
http { url = "https://siem.example.com/CANARYPATH"
 token = "env://T"
 format = "json"
 delivery_guarantee = "enforced" }`,
	}
	for name, sink := range invalid {
		t.Run("invalid "+name, func(t *testing.T) {
			_, err := Parse(eventsHCL(sink))
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "not yet supported")
			for _, leak := range []string{"CANARYPATH", "CANARYSECRET"} {
				assert.NotContains(t, err.Error(), leak)
			}
		})
	}
}
