-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  -- The runbook API authorizes with explicit grants of type=runbook. The
  -- iam_grant table references iam_grant_resource_enm, so without this row a
  -- role grant such as "ids=*;type=runbook;actions=read,list,delete" cannot be
  -- stored (foreign key violation). Add the resource type to the enumeration
  -- and to its check constraint.
  alter table iam_grant_resource_enm
    drop constraint only_predefined_resource_types_allowed;
  alter table iam_grant_resource_enm
    add constraint only_predefined_resource_types_allowed
      check(
        name in (
          '*',
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
  values ('runbook');
commit;
