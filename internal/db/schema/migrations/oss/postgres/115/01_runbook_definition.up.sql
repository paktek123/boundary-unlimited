-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  -- Inert schema for runbook definitions. It mirrors internal/runbook. Nothing
  -- reads or writes this table yet, and no API, CLI or grant action is added
  -- here, so no runbook can be created or run through Boundary.

  create table runbook_definition (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_fkey
        references iam_scope(public_id)
        on delete cascade
        on update cascade,
    name text not null
      constraint name_must_not_be_empty
        check(length(trim(name)) > 0)
      constraint name_must_be_at_most_64_bytes
        check(octet_length(name) <= 64),
    description text
      constraint description_must_be_at_most_4096_bytes
        check(octet_length(description) <= 4096),
    interpreter text not null
      constraint only_supported_interpreters_allowed
        check(interpreter in ('sh')),
    -- the script is only ever fetched at this full commit SHA; branches, tags
    -- and abbreviated SHAs are rejected.
    source_commit_sha text not null
      constraint source_commit_sha_must_be_pinned_40_hex
        check(source_commit_sha ~ '^[0-9a-f]{40}$'),
    script_path text not null
      constraint script_path_must_not_be_empty
        check(length(script_path) > 0)
      constraint script_path_must_be_at_most_512_bytes
        check(octet_length(script_path) <= 512),
    -- hex sha-256 of the exact script bytes, verified again before execution.
    script_sha256 text not null
      constraint script_sha256_must_be_sha256_hex
        check(script_sha256 ~ '^[0-9a-f]{64}$'),
    -- validated parameter declarations (runbook.Parameter list) as JSON.
    parameters jsonb not null default '[]'::jsonb
      constraint parameters_must_be_a_json_array
        check(jsonb_typeof(parameters) = 'array'),
    -- validated target selector (runbook.TargetSelector) as JSON. The empty
    -- object selects nothing.
    target_selector jsonb not null default '{}'::jsonb
      constraint target_selector_must_be_a_json_object
        check(jsonb_typeof(target_selector) = 'object'),
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    constraint runbook_definition_scope_id_name_uq
      unique(scope_id, name),
    constraint runbook_definition_scope_id_public_id_uq
      unique(scope_id, public_id)
  );
  comment on table runbook_definition is
    'runbook_definition is a table where each row is a reviewable, pinned runbook definition. '
    'Nothing creates these rows yet.';

  create trigger immutable_columns before update on runbook_definition
    for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

  create trigger update_version_column after update on runbook_definition
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on runbook_definition
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on runbook_definition
    for each row execute procedure default_create_time();

commit;
