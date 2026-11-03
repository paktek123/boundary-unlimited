-- Copyright IBM Corp. 2020, 2026
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- Inert schema for just-in-time access requests. It mirrors the domain model
  -- in internal/accessrequest. Nothing reads or writes these tables yet, and
  -- no permission or grant action is added here.

  create table access_request_state_enm (
    name text primary key
      constraint only_predefined_access_request_states_allowed
      check (
        name in ('pending', 'approved', 'denied', 'cancelled', 'expired', 'revoked')
      )
  );
  comment on table access_request_state_enm is
    'access_request_state_enm is an enumeration table for the lifecycle states of an access request.';

  insert into access_request_state_enm (name)
  values
    ('pending'),
    ('approved'),
    ('denied'),
    ('cancelled'),
    ('expired'),
    ('revoked');

  create trigger immutable_columns before update on access_request_state_enm
    for each row execute procedure immutable_columns('name');

  create table access_request_decision_enm (
    name text primary key
      constraint only_predefined_access_request_decisions_allowed
      check (
        name in ('approved', 'denied')
      )
  );
  comment on table access_request_decision_enm is
    'access_request_decision_enm is an enumeration table for the decision an approver can record.';

  insert into access_request_decision_enm (name)
  values
    ('approved'),
    ('denied');

  create trigger immutable_columns before update on access_request_decision_enm
    for each row execute procedure immutable_columns('name');

  create table access_request (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_fkey
        references iam_scope(public_id)
        on delete cascade
        on update cascade,
    requester_id wt_user_id
      constraint iam_user_fkey
        references iam_user(public_id)
        on delete cascade
        on update cascade,
    -- snapshot of the requested grant strings
    grants text[] not null
      constraint grants_must_not_be_empty
        check(cardinality(grants) > 0 and cardinality(grants) <= 64),
    -- hex sha-256 of the normalised grants (see accessrequest.GrantHash).
    -- An approval is bound to this hash, so it is set at creation and immutable.
    grant_hash text not null
      constraint grant_hash_must_be_sha256_hex
        check(grant_hash ~ '^[0-9a-f]{64}$'),
    justification text not null
      constraint justification_must_not_be_empty
        check(length(trim(justification)) > 0)
      constraint justification_must_be_at_most_1024_bytes
        check(octet_length(justification) <= 1024),
    state text not null default 'pending'
      constraint access_request_state_enm_fkey
        references access_request_state_enm(name)
        on delete restrict
        on update cascade,
    -- requested access duration in seconds
    ttl_seconds int not null
      constraint ttl_seconds_must_be_greater_than_0
        check(ttl_seconds > 0),
    create_time wt_timestamp,
    update_time wt_timestamp,
    -- set when the request is approved
    expiry_time timestamp with time zone,
    version wt_version,
    constraint approved_request_must_have_expiry_time
      check(state <> 'approved' or expiry_time is not null),
    constraint access_request_scope_id_public_id_uq
      unique(scope_id, public_id)
  );
  comment on table access_request is
    'access_request is a table where each row is a request for time-bounded access. '
    'Nothing creates these rows yet.';

  create index access_request_requester_id_idx on access_request (requester_id);
  create index access_request_state_idx on access_request (state);

  create trigger immutable_columns before update on access_request
    for each row execute procedure immutable_columns('public_id', 'scope_id', 'requester_id', 'grants', 'grant_hash', 'create_time');

  create trigger update_version_column after update on access_request
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on access_request
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on access_request
    for each row execute procedure default_create_time();

  -- Requests only move forward: pending -> any other state, approved ->
  -- expired or revoked. denied, cancelled, expired and revoked are terminal
  -- and the whole row is frozen once a request reaches one of them.
  create function access_request_enforce_transition() returns trigger
  as $$
  begin
    if old.state in ('denied', 'cancelled', 'expired', 'revoked') then
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
    'access_request_enforce_transition makes access request states move forward only and freezes terminal requests.';

  create trigger access_request_enforce_transition before update on access_request
    for each row execute function access_request_enforce_transition();

  insert into oplog_ticket
    (name,             version)
  values
    ('access_request', 1)
  on conflict do nothing;

  create table access_request_approval (
    request_id wt_public_id
      constraint access_request_fkey
        references access_request(public_id)
        on delete cascade
        on update cascade,
    approver_id wt_user_id
      constraint iam_user_fkey
        references iam_user(public_id)
        on delete cascade
        on update cascade,
    decision text not null
      constraint access_request_decision_enm_fkey
        references access_request_decision_enm(name)
        on delete restrict
        on update cascade,
    create_time wt_timestamp,
    -- one approver decides once
    primary key(request_id, approver_id)
  );
  comment on table access_request_approval is
    'access_request_approval is a table where each row records one approver''s decision on an access request. '
    'Nothing creates these rows yet.';

  create index access_request_approval_approver_id_idx on access_request_approval (approver_id);

  create trigger immutable_columns before update on access_request_approval
    for each row execute procedure immutable_columns('request_id', 'approver_id', 'decision', 'create_time');

  create trigger default_create_time_column before insert on access_request_approval
    for each row execute procedure default_create_time();

  -- Defence in depth: the requester can never decide their own request, and
  -- decisions can only be recorded while the request is pending.
  create function access_request_approval_validate() returns trigger
  as $$
  declare
    req access_request%rowtype;
  begin
    select * into req from access_request where public_id = new.request_id;
    if not found then
      raise exception 'access_request % not found', new.request_id using errcode = '23503';
    end if;
    if req.requester_id = new.approver_id then
      raise exception 'approver must differ from requester' using errcode = '23514';
    end if;
    if req.state <> 'pending' then
      raise exception 'access_request % is not pending', new.request_id using errcode = '23514';
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function access_request_approval_validate is
    'access_request_approval_validate rejects self-approval and decisions on requests that are not pending.';

  create trigger access_request_approval_validate before insert on access_request_approval
    for each row execute function access_request_approval_validate();
commit;
