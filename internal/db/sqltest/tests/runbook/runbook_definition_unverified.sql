-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  select plan(4);

  select wtt_load('widgets', 'iam', 'kms');

  -- the explicit unverified state (empty script hash) is accepted
  insert into runbook_definition
    (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values
    ('rb_______01', 'p____bwidget', 'unverified-one', 'sh', repeat('a', 40), 'runbooks/a.sh', '');
  select is(script_sha256, '') from runbook_definition where public_id = 'rb_______01';

  -- a verified hash is still accepted
  insert into runbook_definition
    (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values
    ('rb_______02', 'p____bwidget', 'verified-one', 'sh', repeat('a', 40), 'runbooks/b.sh', repeat('b', 64));
  select is(script_sha256, repeat('b', 64)) from runbook_definition where public_id = 'rb_______02';

  -- malformed hashes are still rejected
  prepare bad_hash as
  insert into runbook_definition (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values ('rb_______03', 'p____bwidget', 'n3', 'sh', repeat('a', 40), 'a.sh', 'nothex');
  select throws_ok('bad_hash', null, null, 'bad script hash succeeded');

  prepare upper_hash as
  insert into runbook_definition (public_id, scope_id, name, interpreter, source_commit_sha, script_path, script_sha256)
  values ('rb_______03', 'p____bwidget', 'n3', 'sh', repeat('a', 40), 'a.sh', repeat('B', 64));
  select throws_ok('upper_hash', null, null, 'upper case hash succeeded');

  select * from finish();
rollback;
