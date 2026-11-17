// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package event

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const netCanary = "CANARYVALUE"

func validHTTP() *HTTPSinkTypeConfig {
	return &HTTPSinkTypeConfig{URL: "https://siem.example.com/" + netCanary, Token: "env://SIEM_TOKEN", Format: HTTPFormatHEC}
}

func validSyslog() *SyslogSinkTypeConfig {
	return &SyslogSinkTypeConfig{Address: "logs.example.com:6514"}
}

func TestHTTPSinkConfig_Validate(t *testing.T) {
	require.NoError(t, validHTTP().Validate())
	cases := map[string]func(c *HTTPSinkTypeConfig){
		"http scheme":     func(c *HTTPSinkTypeConfig) { c.URL = "http://siem.example.com/" + netCanary },
		"userinfo":        func(c *HTTPSinkTypeConfig) { c.URL = "https://u:" + netCanary + "@siem.example.com/" },
		"inline token":    func(c *HTTPSinkTypeConfig) { c.Token = netCanary + "0123456789" },
		"relative file":   func(c *HTTPSinkTypeConfig) { c.Token = "file://rel/" + netCanary },
		"bad env name":    func(c *HTTPSinkTypeConfig) { c.Token = "env://a b" },
		"bad format":      func(c *HTTPSinkTypeConfig) { c.Format = "xml" },
		"wildcard cidr":   func(c *HTTPSinkTypeConfig) { c.AllowPrivateCIDRs = []string{"0.0.0.0/0"} },
		"wildcard cidr6":  func(c *HTTPSinkTypeConfig) { c.AllowPrivateCIDRs = []string{"::/0"} },
		"bad cidr":        func(c *HTTPSinkTypeConfig) { c.AllowPrivateCIDRs = []string{netCanary} },
		"enforced":        func(c *HTTPSinkTypeConfig) { c.DeliveryGuarantee = string(Enforced) },
		"unknown deliver": func(c *HTTPSinkTypeConfig) { c.DeliveryGuarantee = "bogus" },
		"empty url":       func(c *HTTPSinkTypeConfig) { c.URL = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validHTTP()
			mutate(c)
			err := c.Validate()
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidParameter)
			assert.NotContains(t, err.Error(), netCanary)
		})
	}
	var nilCfg *HTTPSinkTypeConfig
	require.Error(t, nilCfg.Validate())
}

func TestSyslogSinkConfig_Validate(t *testing.T) {
	require.NoError(t, validSyslog().Validate(), "tls is the default")
	ok := validSyslog()
	ok.Network, ok.InsecurePlaintext = SyslogNetworkTCP, true
	require.NoError(t, ok.Validate())
	tlsOpts := validSyslog()
	tlsOpts.CAFile = "file:///etc/ca.pem"
	tlsOpts.ClientCertFile, tlsOpts.ClientKeyFile = "file:///etc/c.pem", "file:///etc/k.pem"
	require.NoError(t, tlsOpts.Validate())

	cases := map[string]func(c *SyslogSinkTypeConfig){
		"plaintext tcp without opt-in": func(c *SyslogSinkTypeConfig) { c.Network = SyslogNetworkTCP },
		"plaintext udp without opt-in": func(c *SyslogSinkTypeConfig) { c.Network = SyslogNetworkUDP },
		"opt-in with tls":              func(c *SyslogSinkTypeConfig) { c.InsecurePlaintext = true },
		"tls options on tcp": func(c *SyslogSinkTypeConfig) {
			c.Network, c.InsecurePlaintext, c.CAFile = SyslogNetworkTCP, true, "file:///etc/ca.pem"
		},
		"unknown network":        func(c *SyslogSinkTypeConfig) { c.Network = "sctp" },
		"no port":                func(c *SyslogSinkTypeConfig) { c.Address = "logs.example.com" },
		"relative ca":            func(c *SyslogSinkTypeConfig) { c.CAFile = "file://rel/" + netCanary },
		"inline ca":              func(c *SyslogSinkTypeConfig) { c.CAFile = netCanary },
		"cert without key":       func(c *SyslogSinkTypeConfig) { c.ClientCertFile = "file:///etc/c.pem" },
		"env key reference":      func(c *SyslogSinkTypeConfig) { c.ClientCertFile, c.ClientKeyFile = "file:///a", "env://K" },
		"wildcard cidr":          func(c *SyslogSinkTypeConfig) { c.AllowPrivateCIDRs = []string{"::/0"} },
		"enforced on syslog":     func(c *SyslogSinkTypeConfig) { c.DeliveryGuarantee = string(Enforced) },
		"enforced and plaintext": func(c *SyslogSinkTypeConfig) { c.Network, c.DeliveryGuarantee = SyslogNetworkUDP, string(Enforced) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validSyslog()
			mutate(c)
			err := c.Validate()
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidParameter)
			assert.NotContains(t, err.Error(), netCanary)
		})
	}
}

// A fully valid network sink is still refused: nothing delivers events yet.
func TestSinkConfig_NetworkSinksNotYetSupported(t *testing.T) {
	for _, sc := range []SinkConfig{
		{Name: "siem", EventTypes: []Type{EveryType}, Format: JSONSinkFormat, Type: HTTPSink, HTTPConfig: validHTTP()},
		{Name: "siem", EventTypes: []Type{EveryType}, Format: JSONSinkFormat, Type: SyslogSink, SyslogConfig: validSyslog()},
	} {
		err := sc.Validate()
		require.ErrorIs(t, err, ErrNetworkSinkNotSupported)
		assert.NotContains(t, err.Error(), netCanary)
	}
	// wrong block for the type, and two blocks, are rejected before that
	bad := SinkConfig{Name: "s", EventTypes: []Type{EveryType}, Format: JSONSinkFormat, Type: HTTPSink, SyslogConfig: validSyslog()}
	err := bad.Validate()
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNetworkSinkNotSupported)
	two := SinkConfig{Name: "s", EventTypes: []Type{EveryType}, Format: JSONSinkFormat, Type: HTTPSink, HTTPConfig: validHTTP(), SyslogConfig: validSyslog()}
	assert.NotErrorIs(t, two.Validate(), ErrNetworkSinkNotSupported)
}

func TestNetworkSinkConfigsRedact(t *testing.T) {
	h, s := validHTTP(), validSyslog()
	for _, v := range []any{h, *h, s, *s} {
		out := fmt.Sprintf("%v %+v %#v %s", v, v, v, v)
		assert.NotContains(t, out, netCanary)
		assert.NotContains(t, out, "SIEM_TOKEN")
		assert.NotContains(t, out, "logs.example.com")
	}
}
