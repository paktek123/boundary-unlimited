-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  -- Registers the oplog ticket for runbook_definition so a database-backed
  -- repository can write through the oplog. Nothing registers that repository
  -- in the controller and no API exists, so no runbook can be created yet.
  insert into oplog_ticket
    (name,                 version)
  values
    ('runbook_definition', 1)
  on conflict do nothing;
commit;
