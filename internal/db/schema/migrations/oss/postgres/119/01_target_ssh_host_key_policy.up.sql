-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  -- Host key policy for ssh targets: the pinned upstream host keys and host
  -- CAs, in authorized_keys format. They are public keys, not secrets. The
  -- policy lives on the target only (no other source, no trust on first use).
  -- Nothing accepts these columns through the API yet; the entries are
  -- validated in code (internal/target/ssh/hostkeypolicy) and the limits here
  -- are a bound on what the database will hold: at most 16 entries and a total
  -- size of 16 entries of 4096 bytes each plus separators.
  alter table target_ssh
    add column host_key_policy_keys text[] not null default '{}',
    add column host_key_policy_cas text[] not null default '{}';

  -- The history table must carry the new columns: the generic hst triggers
  -- copy only columns present in both tables, so without this the changes of
  -- the pinned trust anchors would not be recorded.
  alter table target_ssh_hst
    add column host_key_policy_keys text[] not null default '{}',
    add column host_key_policy_cas text[] not null default '{}';

  -- Element validation (NULL elements, key syntax) is done in the domain layer;
  -- array_to_string skips NULL elements.
  alter table target_ssh
    add constraint host_key_policy_keys_count_limit
      check(cardinality(host_key_policy_keys) <= 16),
    add constraint host_key_policy_keys_size_limit
      check(octet_length(array_to_string(host_key_policy_keys, E'\n')) <= 65552),
    add constraint host_key_policy_cas_count_limit
      check(cardinality(host_key_policy_cas) <= 16),
    add constraint host_key_policy_cas_size_limit
      check(octet_length(array_to_string(host_key_policy_cas, E'\n')) <= 65552);

  comment on column target_ssh.host_key_policy_keys is
    'host_key_policy_keys are the pinned upstream host public keys in authorized_keys format.';
  comment on column target_ssh.host_key_policy_cas is
    'host_key_policy_cas are the trusted upstream host CA public keys in authorized_keys format.';
commit;
