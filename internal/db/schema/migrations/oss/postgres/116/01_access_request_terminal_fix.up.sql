-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  -- Migration 114 froze terminal access requests, but update_version_column()
  -- (an after update trigger) issues a nested update that bumps version. The
  -- nested update saw a terminal old.state and was rejected, so no request could
  -- ever move into denied, cancelled, expired or revoked.
  --
  -- A terminal row stays frozen. The only update allowed is the nested version
  -- bump issued by update_version_column(): trigger depth above 1, the same
  -- state, every column other than version and update_time unchanged, and
  -- version incremented by exactly one. Everything else still raises 23601.
  create or replace function access_request_enforce_transition() returns trigger
  as $$
  begin
    if old.state in ('denied', 'cancelled', 'expired', 'revoked') then
      if pg_trigger_depth() > 1
         and new.state = old.state
         and (to_jsonb(new) - 'version' - 'update_time') = (to_jsonb(old) - 'version' - 'update_time')
         and new.version = old.version + 1 then
        return new;
      end if;
      raise exception 'access_request % is in terminal state % and cannot be changed', old.public_id, old.state
        using errcode = '23601';
    end if;
    if new.state is distinct from old.state then
      if old.state = 'pending' and new.state in ('approved', 'denied', 'cancelled', 'expired') then
        return new;
      end if;
      if old.state = 'approved' and new.state in ('expired', 'revoked') then
        return new;
      end if;
      raise exception 'invalid access_request state transition % -> %', old.state, new.state
        using errcode = '23601';
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function access_request_enforce_transition is
    'access_request_enforce_transition makes access request states move forward only and freezes terminal requests, except for the nested version bump issued by update_version_column.';
commit;
