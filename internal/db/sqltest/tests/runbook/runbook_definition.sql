-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  select plan(14);

  select wtt_load('widgets', 'iam', 'kms');

  insert into runbook_definition
    (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values
    ('rb_______01', 'p____bwidget', 'restart-service', 'sh', repeat('a', 40), 'runbooks/restart.sh', repeat('b', 64));
  select is(version::bigint, 1::bigint) from runbook_definition where public_id = 'rb_______01';
  select is(parameters, '[]'::jsonb) from runbook_definition where public_id = 'rb_______01';
  -- the default selector selects nothing
  select is(target_selector, '{}'::jsonb) from runbook_definition where public_id = 'rb_______01';

  -- floating refs and short SHAs are rejected
  prepare branch_ref as
  insert into runbook_definition (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values ('rb_______02', 'p____bwidget', 'n2', 'sh', 'main', 'a.sh', repeat('b', 64));
  select throws_ok('branch_ref', null, null, 'branch ref succeeded');

  prepare short_sha as
  insert into runbook_definition (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values ('rb_______02', 'p____bwidget', 'n2', 'sh', 'abc1234', 'a.sh', repeat('b', 64));
  select throws_ok('short_sha', null, null, 'short sha succeeded');

  prepare upper_sha as
  insert into runbook_definition (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values ('rb_______02', 'p____bwidget', 'n2', 'sh', repeat('A', 40), 'a.sh', repeat('b', 64));
  select throws_ok('upper_sha', null, null, 'upper case sha succeeded');

  prepare bad_script_hash as
  insert into runbook_definition (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values ('rb_______02', 'p____bwidget', 'n2', 'sh', repeat('a', 40), 'a.sh', 'nothex');
  select throws_ok('bad_script_hash', null, null, 'bad script hash succeeded');

  prepare bad_interpreter as
  insert into runbook_definition (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values ('rb_______02', 'p____bwidget', 'n2', 'bash', repeat('a', 40), 'a.sh', repeat('b', 64));
  select throws_ok('bad_interpreter', null, null, 'unsupported interpreter succeeded');

  prepare blank_name as
  insert into runbook_definition (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values ('rb_______02', 'p____bwidget', '  ', 'sh', repeat('a', 40), 'a.sh', repeat('b', 64));
  select throws_ok('blank_name', null, null, 'blank name succeeded');

  prepare params_not_array as
  insert into runbook_definition (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256, parameters)
  values ('rb_______02', 'p____bwidget', 'n2', 'sh', repeat('a', 40), 'a.sh', repeat('b', 64), '{}'::jsonb);
  select throws_ok('params_not_array', null, null, 'non-array parameters succeeded');

  prepare duplicate_name as
  insert into runbook_definition (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values ('rb_______03', 'p____bwidget', 'restart-service', 'sh', repeat('a', 40), 'a.sh', repeat('b', 64));
  select throws_ok('duplicate_name', null, null, 'duplicate name in scope succeeded');

  -- the pin may move only through an update, and identity columns are immutable
  prepare change_scope as
  update runbook_definition set scope_id = 'o_____widget' where public_id = 'rb_______01';
  select throws_ok('change_scope', null, null, 'scope change succeeded');

  update runbook_definition set description = 'changed' where public_id = 'rb_______01';
  select is(version::bigint, 2::bigint) from runbook_definition where public_id = 'rb_______01';

  -- deleting the scope cascades
  delete from iam_scope where public_id = 'p____bwidget';
  select is(count(*), 0::bigint) from runbook_definition where public_id = 'rb_______01';

  select * from finish();
rollback;
