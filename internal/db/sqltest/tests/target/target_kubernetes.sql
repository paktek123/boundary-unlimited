-- Copyright IBM Corp. 2020, 2026
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(16);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- valid insert shows up in target and in target_all_subtypes with the right type
  insert into target_kubernetes
    (project_id, public_id, name)
  values
    ('p____bwidget', 'tkube_____wb', 'Big Widget Kubernetes Target'),
    ('p____swidget', 'tkube_____ws', 'Small Widget Kubernetes Target');

  select is(count(*), 1::bigint) from target_all_subtypes where public_id = 'tkube_____wb';
  select is(type,     'kubernetes') from target_all_subtypes where public_id = 'tkube_____wb';
  select is(count(*), 1::bigint) from target where public_id = 'tkube_____wb';
  select is(count(*), 1::bigint) from target_all_subtypes where public_id = 't_________wb';
  select is(type,     'tcp')     from target_all_subtypes where public_id = 't_________wb';

  -- defaults
  select is(session_max_seconds,      28800) from target_kubernetes where public_id = 'tkube_____wb';
  select is(session_connection_limit, 1)     from target_kubernetes where public_id = 'tkube_____wb';

  -- a duplicate name in the same project is rejected
  prepare duplicate_name as
  insert into target_kubernetes (project_id, public_id, name)
  values ('p____bwidget', 'tkube_____w2', 'Big Widget Kubernetes Target');
  select throws_ok('duplicate_name', null, null, 'duplicate kubernetes target name in a project succeeded');

  -- invalid limits are rejected
  prepare bad_max_seconds as
  update target_kubernetes set session_max_seconds = 0 where public_id = 'tkube_____wb';
  select throws_ok('bad_max_seconds', null, null, 'zero session_max_seconds succeeded');

  prepare bad_connection_limit as
  update target_kubernetes set session_connection_limit = 0 where public_id = 'tkube_____wb';
  select throws_ok('bad_connection_limit', null, null, 'zero session_connection_limit succeeded');

  -- immutable columns
  prepare update_project_id as
  update target_kubernetes set project_id = 'p____swidget' where public_id = 'tkube_____wb';
  select throws_ok('update_project_id', null, null, 'update of project_id succeeded');

  prepare update_public_id as
  update target_kubernetes set public_id = 'tkube_____xx' where public_id = 'tkube_____wb';
  select throws_ok('update_public_id', null, null, 'update of public_id succeeded');

  prepare update_create_time as
  update target_kubernetes set create_time = '2000-01-01 00:00:00+00' where public_id = 'tkube_____wb';
  select throws_ok('update_create_time', null, null, 'update of create_time succeeded');

  -- deleting the target cascades to the subtype row and records the deletion
  delete from target where public_id = 'tkube_____ws';
  select is(count(*), 0::bigint) from target_kubernetes where public_id = 'tkube_____ws';
  select is(count(*), 1::bigint) from target_kubernetes_deleted where public_id = 'tkube_____ws';
  select is(count(*), 1::bigint) from target_all_subtypes_deleted_view where public_id = 'tkube_____ws';

  select * from finish();
rollback;
