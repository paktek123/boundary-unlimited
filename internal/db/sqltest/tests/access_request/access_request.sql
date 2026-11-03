-- Copyright IBM Corp. 2020, 2026
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(26);

  select wtt_load('widgets', 'iam', 'kms');

  -- valid insert; defaults
  insert into access_request
    (public_id, scope_id, requester_id, grants, grant_hash, justification, ttl_seconds)
  values
    ('ar_______01', 'p____bwidget', 'u_____walter', array['ids=*;type=target;actions=read'],
     '0000000000000000000000000000000000000000000000000000000000000001', 'need to debug', 3600),
    ('ar_______02', 'p____bwidget', 'u_____walter', array['ids=*;type=target;actions=read'],
     '0000000000000000000000000000000000000000000000000000000000000001', 'need to debug', 3600);
  select is(state, 'pending') from access_request where public_id = 'ar_______01';
  select is(version, 1::bigint) from access_request where public_id = 'ar_______01';

  -- invalid inputs
  prepare bad_state as
  insert into access_request (public_id, scope_id, requester_id, grants, grant_hash, justification, ttl_seconds, state)
  values ('ar_______03', 'p____bwidget', 'u_____walter', array['a'], repeat('a', 64), 'x', 60, 'bogus');
  select throws_ok('bad_state', null, null, 'invalid state succeeded');

  prepare no_grants as
  insert into access_request (public_id, scope_id, requester_id, grants, grant_hash, justification, ttl_seconds)
  values ('ar_______03', 'p____bwidget', 'u_____walter', array[]::text[], repeat('a', 64), 'x', 60);
  select throws_ok('no_grants', null, null, 'empty grants succeeded');

  prepare bad_hash as
  insert into access_request (public_id, scope_id, requester_id, grants, grant_hash, justification, ttl_seconds)
  values ('ar_______03', 'p____bwidget', 'u_____walter', array['a'], 'nothex', 'x', 60);
  select throws_ok('bad_hash', null, null, 'bad grant hash succeeded');

  prepare blank_justification as
  insert into access_request (public_id, scope_id, requester_id, grants, grant_hash, justification, ttl_seconds)
  values ('ar_______03', 'p____bwidget', 'u_____walter', array['a'], repeat('a', 64), '   ', 60);
  select throws_ok('blank_justification', null, null, 'blank justification succeeded');

  prepare long_justification as
  insert into access_request (public_id, scope_id, requester_id, grants, grant_hash, justification, ttl_seconds)
  values ('ar_______03', 'p____bwidget', 'u_____walter', array['a'], repeat('a', 64), repeat('x', 1025), 60);
  select throws_ok('long_justification', null, null, 'oversized justification succeeded');

  prepare zero_ttl as
  insert into access_request (public_id, scope_id, requester_id, grants, grant_hash, justification, ttl_seconds)
  values ('ar_______03', 'p____bwidget', 'u_____walter', array['a'], repeat('a', 64), 'x', 0);
  select throws_ok('zero_ttl', null, null, 'zero ttl succeeded');

  prepare unknown_requester as
  insert into access_request (public_id, scope_id, requester_id, grants, grant_hash, justification, ttl_seconds)
  values ('ar_______03', 'p____bwidget', 'u_unknownusr', array['a'], repeat('a', 64), 'x', 60);
  select throws_ok('unknown_requester', null, null, 'unknown requester succeeded');

  -- immutable columns
  prepare update_requester as
  update access_request set requester_id = 'u_____warren' where public_id = 'ar_______01';
  select throws_ok('update_requester', null, null, 'update of requester_id succeeded');

  prepare update_grants as
  update access_request set grants = array['ids=*;type=*;actions=*'] where public_id = 'ar_______01';
  select throws_ok('update_grants', null, null, 'update of grants succeeded');

  prepare update_hash as
  update access_request set grant_hash = repeat('b', 64) where public_id = 'ar_______01';
  select throws_ok('update_hash', null, null, 'update of grant_hash succeeded');

  prepare update_create_time as
  update access_request set create_time = '2000-01-01 00:00:00+00' where public_id = 'ar_______01';
  select throws_ok('update_create_time', null, null, 'update of create_time succeeded');

  prepare update_scope as
  update access_request set scope_id = 'p____swidget' where public_id = 'ar_______01';
  select throws_ok('update_scope', null, null, 'update of scope_id succeeded');

  -- approved requires an expiry time
  prepare approve_without_expiry as
  update access_request set state = 'approved' where public_id = 'ar_______01';
  select throws_ok('approve_without_expiry', null, null, 'approved without expiry_time succeeded');

  -- approvals: valid, self-approval, duplicate, unknown approver
  insert into access_request_approval (request_id, approver_id, decision)
  values ('ar_______01', 'u_____warren', 'approved');
  select is(count(*), 1::bigint) from access_request_approval where request_id = 'ar_______01';

  prepare self_approval as
  insert into access_request_approval (request_id, approver_id, decision)
  values ('ar_______02', 'u_____walter', 'approved');
  select throws_ok('self_approval', null, null, 'self-approval succeeded');

  prepare duplicate_approval as
  insert into access_request_approval (request_id, approver_id, decision)
  values ('ar_______01', 'u_____warren', 'denied');
  select throws_ok('duplicate_approval', null, null, 'duplicate approval succeeded');

  prepare bad_decision as
  insert into access_request_approval (request_id, approver_id, decision)
  values ('ar_______02', 'u_____warren', 'maybe');
  select throws_ok('bad_decision', null, null, 'invalid decision succeeded');

  prepare update_decision as
  update access_request_approval set decision = 'denied' where request_id = 'ar_______01';
  select throws_ok('update_decision', null, null, 'update of decision succeeded');

  -- state transitions: pending -> approved (with expiry) -> revoked; terminal is frozen
  update access_request set state = 'approved', expiry_time = now() + interval '1 hour' where public_id = 'ar_______01';
  select is(state, 'approved') from access_request where public_id = 'ar_______01';

  prepare approval_on_non_pending as
  insert into access_request_approval (request_id, approver_id, decision)
  values ('ar_______01', 'u_____waylon', 'approved');
  select throws_ok('approval_on_non_pending', null, null, 'approval on non-pending request succeeded');

  prepare approved_to_pending as
  update access_request set state = 'pending' where public_id = 'ar_______01';
  select throws_ok('approved_to_pending', null, null, 'backwards transition succeeded');

  update access_request set state = 'revoked' where public_id = 'ar_______01';
  prepare terminal_change as
  update access_request set justification = 'changed' where public_id = 'ar_______01';
  select throws_ok('terminal_change', null, null, 'update of a terminal request succeeded');

  -- deleting a requester cascades to their requests and the approvals on them
  delete from iam_user where public_id = 'u_____walter';
  select is(count(*), 0::bigint) from access_request where public_id in ('ar_______01', 'ar_______02');
  select is(count(*), 0::bigint) from access_request_approval where request_id = 'ar_______01';

  select * from finish();
rollback;
