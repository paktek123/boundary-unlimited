// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package event

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrNetworkSinkNotSupported is returned for every valid network (http or
// syslog) sink configuration until the delivery wiring exists. Accepting the
// configuration without delivering events would give a false sense of audit
// streaming (enforcement-first), so the configuration fails closed.
var ErrNetworkSinkNotSupported = errors.New("network event sinks (http, syslog) are not yet supported: no delivery is wired")

const (
	secretEnvPrefix  = "env://"
	secretFilePrefix = "file://"

	// SyslogNetworkTLS, SyslogNetworkTCP and SyslogNetworkUDP are the syslog
	// transports. TLS is the default.
	SyslogNetworkTLS = "tls"
	SyslogNetworkTCP = "tcp"
	SyslogNetworkUDP = "udp"

	// HTTPFormatHEC and HTTPFormatJSON are the request body formats.
	HTTPFormatHEC  = "hec"
	HTTPFormatJSON = "json"
)

var secretEnvNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// HTTPSinkTypeConfig configures an https event sink (Splunk HEC or generic
// JSON webhook). The token is a secret reference, never an inline value.
type HTTPSinkTypeConfig struct {
	URL               string   `hcl:"url"`
	Token             string   `hcl:"token"` // env://NAME or file:///abs/path
	Format            string   `hcl:"format"`
	AllowPrivateCIDRs []string `hcl:"allow_private_cidrs"`
	DeliveryGuarantee string   `hcl:"delivery_guarantee"`
}

// SyslogSinkTypeConfig configures an RFC 5424 syslog event sink.
type SyslogSinkTypeConfig struct {
	Network           string   `hcl:"network"` // tls (default), tcp or udp
	Address           string   `hcl:"address"` // host:port
	InsecurePlaintext bool     `hcl:"insecure_plaintext"`
	CAFile            string   `hcl:"ca_file"`          // file:///abs/path
	ClientCertFile    string   `hcl:"client_cert_file"` // file:///abs/path
	ClientKeyFile     string   `hcl:"client_key_file"`  // file:///abs/path
	AllowPrivateCIDRs []string `hcl:"allow_private_cidrs"`
	DeliveryGuarantee string   `hcl:"delivery_guarantee"`
}

// Redaction: the url, address and secret references never appear when the
// configs are printed.
func (HTTPSinkTypeConfig) String() string     { return "event.HTTPSinkTypeConfig{redacted}" }
func (HTTPSinkTypeConfig) GoString() string   { return "event.HTTPSinkTypeConfig{redacted}" }
func (SyslogSinkTypeConfig) String() string   { return "event.SyslogSinkTypeConfig{redacted}" }
func (SyslogSinkTypeConfig) GoString() string { return "event.SyslogSinkTypeConfig{redacted}" }

func netSinkErr(why string) error {
	return fmt.Errorf("%w: %s", ErrInvalidParameter, why)
}

func validateSecretRef(what, ref string) error {
	switch {
	case strings.HasPrefix(ref, secretEnvPrefix):
		if !secretEnvNameRe.MatchString(strings.TrimPrefix(ref, secretEnvPrefix)) {
			return netSinkErr(what + " env reference is malformed")
		}
	case strings.HasPrefix(ref, secretFilePrefix):
		if !filepath.IsAbs(strings.TrimPrefix(ref, secretFilePrefix)) {
			return netSinkErr(what + " file reference must be an absolute path")
		}
	default:
		return netSinkErr(what + " must be an env:// or file:// reference, inline values are not allowed")
	}
	return nil
}

func validateFileRef(what, ref string) error {
	if !strings.HasPrefix(ref, secretFilePrefix) || !filepath.IsAbs(strings.TrimPrefix(ref, secretFilePrefix)) {
		return netSinkErr(what + " must be a file:// reference with an absolute path")
	}
	return nil
}

func validateAllowCIDRs(cidrs []string) error {
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return netSinkErr("allow_private_cidrs contains an invalid prefix")
		}
		// Wildcards would remove the SSRF protection of the guarded dialer.
		if p.Bits() == 0 {
			return netSinkErr("allow_private_cidrs must not contain a wildcard prefix")
		}
	}
	return nil
}

func validateNetworkDelivery(g string) error {
	switch DeliveryGuarantee(g) {
	case DefaultDeliveryGuarantee, BestEffort:
		return nil
	case Enforced:
		return netSinkErr("network sinks are best-effort and cannot satisfy delivery_guarantee = enforced")
	}
	return netSinkErr("unknown delivery_guarantee")
}

// Validate strictly validates the http sink configuration. Errors never echo
// the url or the token reference.
func (c *HTTPSinkTypeConfig) Validate() error {
	if c == nil {
		return netSinkErr(`missing "http" block`)
	}
	u, err := url.Parse(c.URL)
	switch {
	case err != nil || u == nil || u.Hostname() == "":
		return netSinkErr("http url is not a valid absolute url")
	case u.Scheme != "https":
		return netSinkErr("http url must use https")
	case u.User != nil:
		return netSinkErr("http url must not contain userinfo")
	case u.Fragment != "" || u.Opaque != "":
		return netSinkErr("http url must not contain a fragment")
	}
	if err := validateSecretRef("http token", c.Token); err != nil {
		return err
	}
	switch c.Format {
	case HTTPFormatHEC, HTTPFormatJSON:
	default:
		return netSinkErr(`http format must be "hec" or "json"`)
	}
	if err := validateAllowCIDRs(c.AllowPrivateCIDRs); err != nil {
		return err
	}
	return validateNetworkDelivery(c.DeliveryGuarantee)
}

// Validate strictly validates the syslog sink configuration. tcp and udp
// require insecure_plaintext = true; TLS options are only valid with tls.
func (c *SyslogSinkTypeConfig) Validate() error {
	if c == nil {
		return netSinkErr(`missing "syslog" block`)
	}
	network := c.Network
	if network == "" {
		network = SyslogNetworkTLS
	}
	switch network {
	case SyslogNetworkTLS:
		if c.InsecurePlaintext {
			return netSinkErr("insecure_plaintext is only valid with network tcp or udp")
		}
	case SyslogNetworkTCP, SyslogNetworkUDP:
		if !c.InsecurePlaintext {
			return netSinkErr("plaintext syslog (tcp, udp) requires insecure_plaintext = true")
		}
		if c.CAFile != "" || c.ClientCertFile != "" || c.ClientKeyFile != "" {
			return netSinkErr("tls options require network tls")
		}
	default:
		return netSinkErr("syslog network must be tls, tcp or udp")
	}
	if host, port, err := net.SplitHostPort(c.Address); err != nil || host == "" || port == "" {
		return netSinkErr("syslog address must be host:port")
	}
	if c.CAFile != "" {
		if err := validateFileRef("syslog ca_file", c.CAFile); err != nil {
			return err
		}
	}
	if (c.ClientCertFile == "") != (c.ClientKeyFile == "") {
		return netSinkErr("client_cert_file and client_key_file must be set together")
	}
	if c.ClientCertFile != "" {
		if err := validateFileRef("syslog client_cert_file", c.ClientCertFile); err != nil {
			return err
		}
		if err := validateFileRef("syslog client_key_file", c.ClientKeyFile); err != nil {
			return err
		}
	}
	if err := validateAllowCIDRs(c.AllowPrivateCIDRs); err != nil {
		return err
	}
	return validateNetworkDelivery(c.DeliveryGuarantee)
}
