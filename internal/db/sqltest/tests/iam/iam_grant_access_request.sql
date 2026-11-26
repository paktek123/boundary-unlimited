-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
select plan(5);
select wtt_load('widgets', 'iam');

select is(
  (select count(*) from iam_grant_resource_enm where name = 'access-request'),
  1::bigint,
  'access-request is an allowed grant resource type'
);

select is(
  (select count(*) from iam_grant_resource_enm where name = 'runbook'),
  1::bigint,
  'runbook is an allowed grant resource type'
);

-- the list stays closed: an unknown type is still refused
prepare insert_resource_bogus as
  insert into iam_grant_resource_enm (name) values ('bogus');
select throws_like(
  'insert_resource_bogus',
  '%only_predefined_resource_types_allowed%',
  'an unlisted resource type is still refused'
);

-- an explicit access-request grant can be stored and resolves its resource
prepare insert_grant_access_request as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=*;type=access-request;actions=approve');
select lives_ok('insert_grant_access_request');
select is(
  (select resource
     from iam_grant
    where canonical_grant = 'ids=*;type=access-request;actions=approve'),
  'access-request',
  'resource should be set to "access-request" by set_resource() trigger'
);

select * from finish();
rollback;
