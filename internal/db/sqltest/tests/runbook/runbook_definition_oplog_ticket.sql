-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  select plan(1);

  -- migration 117 registers the oplog ticket the DB-backed repository needs
  select is(count(*), 1::bigint) from oplog_ticket where name = 'runbook_definition';

  select * from finish();
rollback;
