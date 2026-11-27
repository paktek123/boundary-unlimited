-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  select plan(20);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- default is an empty policy
  insert into target_ssh (project_id, public_id, name)
  values ('p____bwidget', 'tssh______p1', 'policy default');
  select is(host_key_policy_keys, '') from target_ssh where public_id = 'tssh______p1';
  select is(host_key_policy_cas, '') from target_ssh where public_id = 'tssh______p1';

  -- one entry, read through target_all_subtypes
  update target_ssh
     set host_key_policy_keys = 'ssh-ed25519 AAAAkey1',
         host_key_policy_cas = 'ssh-ed25519 AAAAca1'
   where public_id = 'tssh______p1';
  select is(host_key_policy_keys, 'ssh-ed25519 AAAAkey1') from target_all_subtypes where public_id = 'tssh______p1';
  select is(host_key_policy_cas, 'ssh-ed25519 AAAAca1') from target_all_subtypes where public_id = 'tssh______p1';

  -- sixteen entries round trip for both lists
  select lives_ok($$update target_ssh set host_key_policy_keys = array_to_string(array(select 'ssh-ed25519 AAAA' || g from generate_series(1, 16) g), E'\n')
     where public_id = 'tssh______p1'$$, '16 host keys refused');
  select lives_ok($$update target_ssh set host_key_policy_cas = array_to_string(array(select 'ssh-ed25519 AAAA' || g from generate_series(1, 16) g), E'\n')
     where public_id = 'tssh______p1'$$, '16 host cas refused');
  select is(host_key_policy_keys, array_to_string(array(select 'ssh-ed25519 AAAA' || g from generate_series(1, 16) g), E'\n')) from target_all_subtypes where public_id = 'tssh______p1';
  select is(host_key_policy_cas, array_to_string(array(select 'ssh-ed25519 AAAA' || g from generate_series(1, 16) g), E'\n')) from target_all_subtypes where public_id = 'tssh______p1';

  -- seventeen entries are refused
  select throws_ok($$update target_ssh set host_key_policy_keys = array_to_string(array(select 'ssh-ed25519 AAAA' || g from generate_series(1, 17) g), E'\n')
     where public_id = 'tssh______p1'$$, '23514', null, 'more than 16 host keys accepted');
  select throws_ok($$update target_ssh set host_key_policy_cas = array_to_string(array(select 'ssh-ed25519 AAAA' || g from generate_series(1, 17) g), E'\n')
     where public_id = 'tssh______p1'$$, '23514', null, 'more than 16 host cas accepted');

  -- size limit
  select lives_ok($$update target_ssh set host_key_policy_keys = repeat('a', 65551)
     where public_id = 'tssh______p1'$$, 'exact max size refused');
  select throws_ok($$update target_ssh set host_key_policy_keys = repeat('a', 65552)
     where public_id = 'tssh______p1'$$, '23514', null, 'max size plus one accepted');
  select throws_ok($$update target_ssh set host_key_policy_cas = repeat('a', 65552)
     where public_id = 'tssh______p1'$$, '23514', null, 'oversized host cas accepted');
  select throws_ok($$update target_ssh set host_key_policy_keys = null
     where public_id = 'tssh______p1'$$, '23502', null, 'null policy accepted');

  -- clearing
  update target_ssh set host_key_policy_keys = '', host_key_policy_cas = '' where public_id = 'tssh______p1';
  select is(host_key_policy_keys || host_key_policy_cas, '') from target_all_subtypes where public_id = 'tssh______p1';

  -- history records the policy (rows are matched by content: all updates share
  -- one transaction timestamp, so valid_range cannot tell them apart here)
  update target_ssh set host_key_policy_keys = 'ssh-ed25519 AAAAold' where public_id = 'tssh______p1';
  update target_ssh set host_key_policy_keys = 'ssh-ed25519 AAAAnew' where public_id = 'tssh______p1';
  select ok(exists(select 1 from target_ssh_hst where public_id = 'tssh______p1'
      and host_key_policy_keys = 'ssh-ed25519 AAAAold'), 'history lacks the old keys');
  select ok(exists(select 1 from target_ssh_hst where public_id = 'tssh______p1'
      and host_key_policy_keys = 'ssh-ed25519 AAAAnew'), 'history lacks the new keys');
  select col_type_is('target_ssh_hst', 'host_key_policy_cas', 'text', 'history cas column is not text');

  -- other target types have an empty policy in the view
  select is(count(*), 0::bigint) from target_all_subtypes
   where type <> 'ssh' and (host_key_policy_keys <> '' or host_key_policy_cas <> '');
  select ok(count(*) > 0, 'view lists no targets') from target_all_subtypes;

  select * from finish();
rollback;
