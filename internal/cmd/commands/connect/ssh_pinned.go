// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package connect

// pinnedHostKeyArgs returns the extra ssh arguments that pin the connection
// to the worker's per-session ephemeral host key, and a cleanup func that
// removes the private known_hosts file written for it. Cleanup is idempotent.
//
// With an empty pin it returns no arguments and a no-op cleanup, leaving
// sshFlags.buildArgs's behaviour unchanged. With a pin it never returns
// NoHostAuthenticationForLocalhost, and the key only appears in the private
// 0600 file, never on the command line. Malformed pins (more than one line,
// options, certificates, non-ed25519 keys) are rejected before anything is
// written. It is not used by the ssh command yet.
func pinnedHostKeyArgs(pin, hostAlias, port string) (args []string, cleanup func(), err error) {
	if pin == "" {
		return nil, func() {}, nil
	}
	opts, cleanup, err := writeKnownHostsPort(hostAlias, port, pin)
	if err != nil {
		return nil, nil, err
	}
	args = make([]string, 0, 2*len(opts))
	for _, o := range opts {
		args = append(args, "-o", o)
	}
	return args, cleanup, nil
}
