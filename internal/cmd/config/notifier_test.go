// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const canaryURL = "https://hooks.example.com/CANARYPATH"

func notifierHCL(body string) string {
	return fmt.Sprintf("notifier \"ops\" {\n%s\n}\n", body)
}

func TestParseNotifier_Valid(t *testing.T) {
	c, err := Parse(notifierHCL(`type = "slack"
url = "` + canaryURL + `"
secret = "env://NOTIFY_SECRET"`))
	require.NoError(t, err)
	require.Len(t, c.Notifiers, 1)
	assert.Equal(t, "ops", c.Notifiers[0].Name)
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", c.Notifiers[0], c.Notifiers, c.Notifiers[0]), "CANARYPATH")
	assert.NotContains(t, fmt.Sprintf("%v", c.Notifiers[0]), "NOTIFY_SECRET")

	c, err = Parse(`controller { name = "c" }`)
	require.NoError(t, err)
	assert.Empty(t, c.Notifiers)
}

func TestParseNotifier_Rejected(t *testing.T) {
	cases := map[string]string{
		"http url":        `type = "webhook"` + "\n" + `url = "http://hooks.example.com/CANARYPATH"` + "\n" + `secret = "env://X"`,
		"userinfo":        `type = "webhook"` + "\n" + `url = "https://user:pw@hooks.example.com/CANARYPATH"` + "\n" + `secret = "env://X"`,
		"inline secret":   `type = "webhook"` + "\n" + `url = "` + canaryURL + `"` + "\n" + `secret = "CANARYSECRETVALUE123456"`,
		"relative file":   `type = "webhook"` + "\n" + `url = "` + canaryURL + `"` + "\n" + `secret = "file://rel/path"`,
		"bad env name":    `type = "webhook"` + "\n" + `url = "` + canaryURL + `"` + "\n" + `secret = "env://a b"`,
		"skip_verify":     `type = "webhook"` + "\n" + `url = "` + canaryURL + `"` + "\n" + `secret = "env://X"` + "\n" + `skip_verify = true`,
		"tls min version": `type = "webhook"` + "\n" + `url = "` + canaryURL + `"` + "\n" + `secret = "env://X"` + "\n" + `tls_min_version = "1.0"`,
		"unknown key":     `type = "webhook"` + "\n" + `url = "` + canaryURL + `"` + "\n" + `secret = "env://X"` + "\n" + `bogus = 1`,
		"unknown type":    `type = "pagerduty"` + "\n" + `url = "` + canaryURL + `"` + "\n" + `secret = "env://X"`,
		"missing url":     `type = "webhook"` + "\n" + `secret = "env://X"`,
		"missing type":    `url = "` + canaryURL + `"` + "\n" + `secret = "env://X"`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(notifierHCL(body))
			require.Error(t, err)
			for _, leak := range []string{"CANARYPATH", "CANARYSECRETVALUE", "user:pw"} {
				assert.NotContains(t, err.Error(), leak)
			}
		})
	}
	_, err := Parse(`notifier { type = "webhook" }`)
	require.Error(t, err, "unlabelled block")
	_, err = Parse(notifierHCL(`type = "slack"`+"\n"+`url = "`+canaryURL+`"`+"\n"+`secret = "env://X"`) + notifierHCL(`type = "slack"`+"\n"+`url = "`+canaryURL+`"`+"\n"+`secret = "env://X"`))
	require.Error(t, err, "duplicate name")
}
