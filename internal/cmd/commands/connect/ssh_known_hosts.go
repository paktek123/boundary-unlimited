// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// maxPinnedKeyLength bounds a pinned public key line; an ed25519 key is far
// smaller.
const maxPinnedKeyLength = 1024

var hostAliasRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// writeKnownHosts writes a private (mode 0600) temporary known_hosts file
// holding only the given public key (authorized_keys format) for the host
// alias. It returns the ssh option set that pins the connection to that file
// and to that alias, and a cleanup func that removes it. It is not used by the ssh command yet.
func writeKnownHosts(hostAlias, authorizedKey string) (opts []string, cleanup func(), retErr error) {
	return writeKnownHostsPort(hostAlias, "", authorizedKey)
}

// writeKnownHostsPort is writeKnownHosts for a connection to a non-default
// port: ssh looks the host key up as "[alias]:port" unless the port is 22. An
// empty port, or 22, uses the plain alias.
func writeKnownHostsPort(hostAlias, port, authorizedKey string) (opts []string, cleanup func(), retErr error) {
	if !hostAliasRe.MatchString(hostAlias) {
		return nil, nil, fmt.Errorf("invalid host alias")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return nil, nil, fmt.Errorf("invalid port")
		}
	}
	if len(authorizedKey) > maxPinnedKeyLength {
		return nil, nil, fmt.Errorf("invalid public key")
	}
	pub, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key")
	}
	if len(options) > 0 {
		return nil, nil, fmt.Errorf("public key options are not allowed")
	}
	for _, r := range strings.TrimSpace(authorizedKey[:len(authorizedKey)-len(rest)]) + comment {
		if r < 0x20 || r == 0x7f {
			return nil, nil, fmt.Errorf("invalid public key")
		}
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, nil, fmt.Errorf("exactly one public key is required")
	}
	// Only plain (non-certificate) Ed25519 keys are used for the ephemeral
	// client-facing host key.
	if pub.Type() != ssh.KeyAlgoED25519 {
		return nil, nil, fmt.Errorf("only ed25519 public keys are supported")
	}

	// os.CreateTemp creates the file with mode 0600.
	f, err := os.CreateTemp("", "boundary-known-hosts-*")
	if err != nil {
		return nil, nil, fmt.Errorf("creating known_hosts file: %w", err)
	}
	name := f.Name()
	cleanup = func() { _ = os.Remove(name) }
	defer func() {
		if retErr != nil {
			cleanup()
		}
	}()
	lookup := hostAlias
	if port != "" && port != "22" {
		lookup = "[" + hostAlias + "]:" + port
	}
	line := lookup + " " + pub.Type() + " " + base64.StdEncoding.EncodeToString(pub.Marshal()) + "\n"
	if _, err := f.WriteString(line); err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("writing known_hosts file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, nil, fmt.Errorf("closing known_hosts file: %w", err)
	}
	return []string{
		"UserKnownHostsFile=" + name,
		"HostKeyAlias=" + hostAlias,
		"StrictHostKeyChecking=yes",
	}, cleanup, nil
}
