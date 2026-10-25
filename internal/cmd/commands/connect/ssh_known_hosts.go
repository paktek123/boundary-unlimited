// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

var hostAliasRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// writeKnownHosts writes a private (mode 0600) temporary known_hosts file
// holding only the given public key (authorized_keys format) for the host
// alias. It returns the ssh option set that pins the connection to that file
// and to that alias, and a cleanup func that removes it. It is not used by the ssh command yet.
func writeKnownHosts(hostAlias, authorizedKey string) (opts []string, cleanup func(), retErr error) {
	if !hostAliasRe.MatchString(hostAlias) {
		return nil, nil, fmt.Errorf("invalid host alias")
	}
	pub, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key")
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
	line := hostAlias + " " + pub.Type() + " " + base64.StdEncoding.EncodeToString(pub.Marshal()) + "\n"
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
