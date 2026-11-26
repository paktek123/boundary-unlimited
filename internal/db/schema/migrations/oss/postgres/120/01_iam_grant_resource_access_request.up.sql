-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  -- A role grant row (iam_grant) references iam_grant_resource_enm by the
  -- resource type named in the grant, and that table only accepts a fixed list
  -- (only_predefined_resource_types_allowed). Without 'access-request' (and
  -- 'runbook', which has the same gap) no role can hold a grant with that
  -- type, so for example approve could never be authorized.
  -- Granting stays explicit: type=* and actions=* never cover these types
  -- (internal/perms); this only lets an explicit grant be stored.
  alter table iam_grant_resource_enm
    drop constraint only_predefined_resource_types_allowed;
  alter table iam_grant_resource_enm
    add constraint only_predefined_resource_types_allowed
      check(
        name in (
          '*',
          'access-request',
          'alias',
          'auth-method',
          'auth-token',
          'account',
          'billing',
          'controller',
          'credential',
          'credential-library',
          'credential-store',
          'group',
          'host',
          'host-catalog',
          'host-set',
          'managed-group',
          'policy',
          'role',
          'runbook',
          'scope',
          'session',
          'session-recording',
          'storage-bucket',
          'target',
          'unknown',
          'user',
          'worker'
        )
      );

  insert into iam_grant_resource_enm (name)
  values
    ('access-request'),
    ('runbook')
  on conflict (name) do nothing;
commit;
