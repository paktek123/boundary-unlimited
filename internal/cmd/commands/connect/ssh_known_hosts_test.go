// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func testAuthorizedKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	k, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func TestWriteKnownHosts(t *testing.T) {
	key := testAuthorizedKey(t)
	opts, cleanup, err := writeKnownHosts("boundary-session-1", key)
	require.NoError(t, err)
	require.NotNil(t, cleanup)

	require.Len(t, opts, 2)
	file := strings.TrimPrefix(opts[0], "UserKnownHostsFile=")
	assert.NotEqual(t, opts[0], file)
	assert.Contains(t, opts, "StrictHostKeyChecking=yes")

	st, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())

	b, err := os.ReadFile(file)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	require.Len(t, lines, 1)
	assert.Equal(t, "boundary-session-1 "+key, lines[0])

	cleanup()
	_, err = os.Stat(file)
	assert.True(t, os.IsNotExist(err))
}

func TestWriteKnownHosts_Invalid(t *testing.T) {
	key := testAuthorizedKey(t)
	for name, tc := range map[string][2]string{
		"empty alias":    {"", key},
		"alias spaces":   {"a b", key},
		"alias newline":  {"a\nb", key},
		"alias wildcard": {"*", key},
		"bad key":        {"alias", "nope"},
		"two keys":       {"alias", key + "\n" + key},
	} {
		t.Run(name, func(t *testing.T) {
			opts, cleanup, err := writeKnownHosts(tc[0], tc[1])
			require.Error(t, err)
			assert.Nil(t, opts)
			assert.Nil(t, cleanup)
		})
	}
}
