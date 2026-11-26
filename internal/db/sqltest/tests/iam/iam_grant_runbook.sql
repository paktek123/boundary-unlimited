-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  select plan(4);

  select wtt_load('widgets', 'iam');

  -- a grant of type runbook can be stored and its resource is derived
  prepare insert_runbook_grant as
    insert into iam_grant (canonical_grant)
    values ('ids=*;type=runbook;actions=read,list,delete');
  select lives_ok('insert_runbook_grant');
  select is(
    (select resource from iam_grant
      where canonical_grant = 'ids=*;type=runbook;actions=read,list,delete'),
    'runbook',
    'resource should be set to "runbook"'
  );

  -- the enumeration still rejects types that are not predefined
  prepare insert_bad_enum as
    insert into iam_grant_resource_enm (name) values ('not-a-resource');
  select throws_ok('insert_bad_enum', null, null, 'unknown resource type was accepted');

  -- and an unknown type in a grant is still refused
  prepare insert_unknown_type_grant as
    insert into iam_grant (canonical_grant)
    values ('ids=*;type=not-a-resource;actions=read');
  select throws_ok('insert_unknown_type_grant', null, null, 'grant with unknown type was accepted');

  select * from finish();
rollback;
