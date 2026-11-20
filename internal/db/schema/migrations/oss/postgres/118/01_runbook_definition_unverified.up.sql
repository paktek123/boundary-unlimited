-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  -- A definition created from a pin reference only (commit and path, no script
  -- bytes) has no script hash yet. The empty string is the explicit
  -- "unverified" state; run and approval binding refuse it in code
  -- (source.Verify fails on an empty hash). Any other value must still be a
  -- full lowercase hex sha-256.
  alter table runbook_definition
    drop constraint script_sha256_must_be_sha256_hex;
  alter table runbook_definition
    add constraint script_sha256_must_be_empty_or_sha256_hex
      check(script_sha256 = '' or script_sha256 ~ '^[0-9a-f]{64}$');
commit;
