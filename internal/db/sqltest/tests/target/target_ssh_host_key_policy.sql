-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  select plan(7);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- default is an empty policy
  insert into target_ssh (project_id, public_id, name)
  values ('p____bwidget', 'tssh______p1', 'policy default');
  select is(cardinality(host_key_policy_keys), 0) from target_ssh where public_id = 'tssh______p1';
  select is(cardinality(host_key_policy_cas), 0) from target_ssh where public_id = 'tssh______p1';

  -- round trip and atomic replace
  update target_ssh
     set host_key_policy_keys = array['ssh-ed25519 AAAAkey1', 'ssh-ed25519 AAAAkey2'],
         host_key_policy_cas = array['ssh-ed25519 AAAAca1']
   where public_id = 'tssh______p1';
  select is(host_key_policy_keys, array['ssh-ed25519 AAAAkey1', 'ssh-ed25519 AAAAkey2'])
    from target_ssh where public_id = 'tssh______p1';
  update target_ssh set host_key_policy_keys = '{}' where public_id = 'tssh______p1';
  select is(cardinality(host_key_policy_keys), 0) from target_ssh where public_id = 'tssh______p1';

  -- too many entries
  prepare too_many as
    update target_ssh
       set host_key_policy_keys = array(select 'ssh-ed25519 AAAA' || g from generate_series(1, 17) g)
     where public_id = 'tssh______p1';
  select throws_ok('too_many', '23514', null, 'more than 16 host keys accepted');

  prepare too_many_cas as
    update target_ssh
       set host_key_policy_cas = array(select 'ssh-ed25519 AAAA' || g from generate_series(1, 17) g)
     where public_id = 'tssh______p1';
  select throws_ok('too_many_cas', '23514', null, 'more than 16 host cas accepted');

  -- oversized entries
  prepare too_big as
    update target_ssh
       set host_key_policy_keys = array[repeat('a', 70000)]
     where public_id = 'tssh______p1';
  select throws_ok('too_big', '23514', null, 'oversized host key policy accepted');

  select * from finish();
rollback;
