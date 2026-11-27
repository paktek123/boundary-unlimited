// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/ssh"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	targetssh "github.com/hashicorp/boundary/internal/target/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func dbTestKeys(t *testing.T, n int) []string {
	t.Helper()
	var out []string
	for i := 0; i < n; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		spk, err := gossh.NewPublicKey(pub)
		require.NoError(t, err)
		out = append(out, strings.TrimSpace(string(gossh.MarshalAuthorizedKey(spk))))
	}
	return out
}

// TestRepository_HostKeyPolicyReadBack checks that every read path returns the
// stored policy: a read that silently yielded "empty" would be fail open.
func TestRepository_HostKeyPolicyReadBack(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	for _, n := range []int{0, 1, 16} {
		t.Run(fmt.Sprintf("%d entries", n), func(t *testing.T) {
			keys, cas := dbTestKeys(t, n), dbTestKeys(t, n)
			tgt, err := target.New(ctx, targetssh.Subtype, proj.PublicId, target.WithName(fmt.Sprintf("policy-%d", n)), target.WithDefaultPort(22))
			require.NoError(t, err)
			require.NoError(t, tgt.(*targetssh.Target).SetHostKeyPolicy(ctx, keys, cas))

			created, err := repo.CreateTarget(ctx, tgt)
			require.NoError(t, err)

			assertPolicy := func(path string, got target.Target) {
				t.Helper()
				require.NotNil(t, got, path)
				gotKeys, gotCas, err := got.(*targetssh.Target).HostKeyPolicy(ctx)
				require.NoError(t, err, path)
				assert.Equal(t, keys, gotKeys, path)
				assert.Equal(t, cas, gotCas, path)
			}
			assertPolicy("create", created)

			found, err := repo.LookupTarget(ctx, created.GetPublicId())
			require.NoError(t, err)
			assertPolicy("lookup", found)
			assert.Equal(t, created.(*targetssh.Target).GetHostKeyPolicyKeys(), found.(*targetssh.Target).GetHostKeyPolicyKeys())
			assert.Equal(t, created.(*targetssh.Target).GetHostKeyPolicyCas(), found.(*targetssh.Target).GetHostKeyPolicyCas())

			// an unrelated update keeps the policy
			upd := found.Clone()
			upd.SetDescription("changed")
			updated, _, err := repo.UpdateTarget(ctx, upd, found.GetVersion(), []string{"Description"})
			require.NoError(t, err)
			assertPolicy("update", updated)

			// an empty policy is refused for a recorded session
			gotKeys, gotCas, err := found.(*targetssh.Target).HostKeyPolicy(ctx)
			require.NoError(t, err)
			_, err = ssh.BuildSessionInput(ctx, ssh.SessionInputArgs{
				SessionId: "s_1234567890", ConnectionId: "sc_1234567890", TargetId: found.GetPublicId(),
				UpstreamAddress: "10.0.0.1:22", PinnedHostKeys: gotKeys, HostCAs: gotCas,
				RecordingEnabled: true, Expiration: time.Now().Add(time.Hour),
			})
			switch n {
			case 0:
				require.Error(t, err)
			case 1:
				require.NoError(t, err)
			}
		})
	}

	// a value written around the domain layer makes the getter fail closed
	t.Run("stored garbage", func(t *testing.T) {
		tgt, err := target.New(ctx, targetssh.Subtype, proj.PublicId, target.WithName("policy-garbage"), target.WithDefaultPort(22))
		require.NoError(t, err)
		created, err := repo.CreateTarget(ctx, tgt)
		require.NoError(t, err)
		_, err = rw.Exec(ctx, "update target_ssh set host_key_policy_keys = 'not a key' where public_id = ?", []any{created.GetPublicId()})
		require.NoError(t, err)
		found, err := repo.LookupTarget(ctx, created.GetPublicId())
		require.NoError(t, err)
		keys, cas, err := found.(*targetssh.Target).HostKeyPolicy(ctx)
		require.Error(t, err)
		assert.Nil(t, keys)
		assert.Nil(t, cas)
	})
}
