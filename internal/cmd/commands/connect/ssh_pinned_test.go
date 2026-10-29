// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPinnedHostKeyArgs(t *testing.T) {
	key := testAuthorizedKey(t)
	args, cleanup, err := pinnedHostKeyArgs(key, "boundary-session-1", "")
	require.NoError(t, err)
	require.NotNil(t, cleanup)

	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "-o StrictHostKeyChecking=yes")
	assert.NotContains(t, joined, "NoHostAuthenticationForLocalhost")
	assert.NotContains(t, joined, strings.Fields(key)[1], "the key must not be on the command line")

	require.NotEmpty(t, args)
	require.Equal(t, "-o", args[0], "first argument must be -o")
	var file string
	for i, a := range args {
		if a == "-o" {
			continue
		}
		assert.Equal(t, "-o", args[i-1], "every option is passed as -o <opt>")
		if strings.HasPrefix(a, "UserKnownHostsFile=") {
			file = strings.TrimPrefix(a, "UserKnownHostsFile=")
		}
	}
	require.NotEmpty(t, file)
	st, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	b, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, "boundary-session-1 "+key+"\n", string(b))

	cleanup()
	_, err = os.Stat(file)
	assert.True(t, os.IsNotExist(err))
	assert.NotPanics(t, cleanup, "cleanup is idempotent")
}

func TestPinnedHostKeyArgs_Port(t *testing.T) {
	key := testAuthorizedKey(t)
	for port, want := range map[string]string{
		"":      "alias ",
		"22":    "alias ",
		"2222":  "[alias]:2222 ",
		"65535": "[alias]:65535 ",
	} {
		args, cleanup, err := pinnedHostKeyArgs(key, "alias", port)
		require.NoError(t, err, port)
		var file string
		for _, a := range args {
			if strings.HasPrefix(a, "UserKnownHostsFile=") {
				file = strings.TrimPrefix(a, "UserKnownHostsFile=")
			}
		}
		b, err := os.ReadFile(file)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(b), want), "port %q: %q", port, b)
		cleanup()
	}
}

func TestPinnedHostKeyArgs_NoPinUnchanged(t *testing.T) {
	args, cleanup, err := pinnedHostKeyArgs("", "alias", "22")
	require.NoError(t, err)
	assert.Empty(t, args)
	require.NotNil(t, cleanup)
	cleanup()
}

func TestPinnedHostKeyArgs_RejectsMalformedBeforeWriting(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	key := testAuthorizedKey(t)
	for name, tc := range map[string]struct{ pin, alias, port string }{
		"newline":        {key + "\n" + key, "alias", ""},
		"trailing line":  {key + "\nfoo", "alias", ""},
		"options":        {`command="id" ` + key, "alias", ""},
		"cert authority": {"cert-authority " + key, "alias", ""},
		"certificate":    {"ssh-ed25519-cert-v01@openssh.com AAAA", "alias", ""},
		"control char":   {key + " a\x01b", "alias", ""},
		"oversize":       {key + " " + strings.Repeat("a", maxPinnedKeyLength), "alias", ""},
		"ecdsa":          {testECDSAKey(t), "alias", ""},
		"garbage":        {"nope", "alias", ""},
		"bad alias":      {key, "a b", ""},
		"bad port":       {key, "alias", "70000"},
		"non numeric":    {key, "alias", "ssh"},
		"leading zero":   {key, "alias", "022"},
	} {
		t.Run(name, func(t *testing.T) {
			args, cleanup, err := pinnedHostKeyArgs(tc.pin, tc.alias, tc.port)
			require.Error(t, err)
			assert.Nil(t, args)
			assert.Nil(t, cleanup)
			entries, derr := os.ReadDir(tmp)
			require.NoError(t, derr)
			assert.Empty(t, entries, "nothing may be written for a rejected pin: %v", tmp)
		})
	}
}
