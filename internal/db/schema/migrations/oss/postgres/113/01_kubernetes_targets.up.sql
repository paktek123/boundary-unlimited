-- Copyright IBM Corp. 2020, 2026
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create table target_kubernetes (
    public_id wt_public_id primary key
      constraint target_fkey
        references target(public_id)
        on delete cascade
        on update cascade,
    project_id wt_scope_id not null,
    name text not null, -- name is not optional for a target subtype
    description text,
    default_port int, -- default port can be null
    -- max duration of the session in seconds. default is 8 hours
    session_max_seconds int not null default 28800
      constraint session_max_seconds_must_be_greater_than_0
      check(session_max_seconds > 0),
    -- limit on number of session connections allowed. -1 equals no limit
    session_connection_limit int not null default 1
      constraint session_connection_limit_must_be_greater_than_0_or_negative_1
      check(session_connection_limit > 0 or session_connection_limit = -1),
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    worker_filter wt_bexprfilter,
    egress_worker_filter wt_bexprfilter,
    ingress_worker_filter wt_bexprfilter,
    default_client_port int,
    constraint target_kubernetes_project_id_name_uq
      unique(project_id, name) -- name must be unique within a project scope.
  );
  comment on table target_kubernetes is
    'target_kubernetes is a table where each row is a resource that represents a kubernetes target. '
    'It is a target subtype. Nothing creates these rows yet.';

  create trigger insert_target_subtype before insert on target_kubernetes
    for each row execute procedure insert_target_subtype();

  create trigger delete_target_subtype after delete on target_kubernetes
    for each row execute procedure delete_target_subtype();

  create trigger immutable_columns before update on target_kubernetes
    for each row execute procedure immutable_columns('public_id', 'project_id', 'create_time');

  create trigger update_version_column after update on target_kubernetes
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on target_kubernetes
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on target_kubernetes
    for each row execute procedure default_create_time();

  create trigger update_kubernetes_target_filter_validate before update on target_kubernetes
    for each row execute procedure validate_filter_values_on_update();

  create trigger insert_kubernetes_target_filter_validate before insert on target_kubernetes
    for each row execute procedure validate_filter_values_on_insert();

  create trigger update_target_table_update_time before update on target_kubernetes
    for each row execute procedure update_target_table_update_time();

  insert into oplog_ticket
    (name,         version)
  values
    ('target_kubernetes', 1)
  on conflict do nothing;

  create table target_kubernetes_hst(
    public_id wt_public_id not null,
    project_id wt_scope_id not null,
    name text not null,
    description text null,
    default_port integer null,
    session_max_seconds integer not null,
    session_connection_limit integer not null,
    worker_filter wt_bexprfilter null,
    egress_worker_filter wt_bexprfilter null,
    ingress_worker_filter wt_bexprfilter null,
    default_client_port integer null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key
      constraint target_history_base_fkey
        references target_history_base (history_id)
        on delete cascade
        on update cascade,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint target_kubernetes_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table target_kubernetes_hst is
    'target_kubernetes_hst is a history table where each row contains the values from a row '
    'in the target_kubernetes table during the time range in the valid_range column.';

  create trigger hst_on_insert after insert on target_kubernetes
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on target_kubernetes
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on target_kubernetes
    for each row execute function hst_on_delete();
  create trigger hst_before_insert before insert on target_kubernetes_hst
    for each row execute function insert_target_history_subtype();
  create trigger hst_after_delete after delete on target_kubernetes_hst
    for each row execute function delete_target_history_subtype();

  create table target_kubernetes_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table target_kubernetes_deleted is
    'target_kubernetes_deleted holds the ID and delete_time of every deleted Kubernetes target. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create index target_kubernetes_deleted_delete_time_idx on target_kubernetes_deleted (delete_time);

  create trigger insert_deleted_id after delete on target_kubernetes
    for each row execute function insert_deleted_id('target_kubernetes_deleted');

  -- replaces target_all_subtypes_deleted_view defined in 98/04_rdp_targets.up.sql
  drop view target_all_subtypes_deleted_view;
  create view target_all_subtypes_deleted_view
  as
    select public_id, delete_time from target_tcp_deleted
    union
    select public_id, delete_time from target_ssh_deleted
    union
    select public_id, delete_time from target_rdp_deleted
    union
    select public_id, delete_time from target_kubernetes_deleted;
  comment on view target_all_subtypes_deleted_view is
    'target_all_subtypes_deleted_view holds the ID and delete_time of every deleted target.';

  -- The whx_* views here depend on target_all_subtypes, so we need to drop
  -- these first.
  drop view whx_host_dimension_source;
  drop view whx_credential_dimension_source;
  drop view target_all_subtypes;

  -- replaces target_all_subtypes defined in 98/04_rdp_targets.up.sql
  create view target_all_subtypes as
  select
    public_id,
    project_id,
    name,
    description,
    default_port,
    session_max_seconds,
    session_connection_limit,
    version,
    create_time,
    update_time,
    worker_filter,
    egress_worker_filter,
    ingress_worker_filter,
    default_client_port,
    null as storage_bucket_id,
    false as enable_session_recording,
    'tcp' as type
  from target_tcp
  union
  select
    public_id,
    project_id,
    name,
    description,
    default_port,
    session_max_seconds,
    session_connection_limit,
    version,
    create_time,
    update_time,
    worker_filter,
    egress_worker_filter,
    ingress_worker_filter,
    default_client_port,
    storage_bucket_id,
    enable_session_recording,
    'ssh' as type
  from
    target_ssh
  union
  select
    public_id,
    project_id,
    name,
    description,
    default_port,
    session_max_seconds,
    session_connection_limit,
    version,
    create_time,
    update_time,
    worker_filter,
    egress_worker_filter,
    ingress_worker_filter,
    default_client_port,
    storage_bucket_id,
    enable_session_recording,
    'rdp' as type
  from
    target_rdp
  union
  select
    public_id,
    project_id,
    name,
    description,
    default_port,
    session_max_seconds,
    session_connection_limit,
    version,
    create_time,
    update_time,
    worker_filter,
    egress_worker_filter,
    ingress_worker_filter,
    default_client_port,
    null as storage_bucket_id,
    false as enable_session_recording,
    'kubernetes' as type
  from
    target_kubernetes;

  -- replaces whx_host_dimension_source defined in 98/04_rdp_targets.up.sql
  create view whx_host_dimension_source as
  with
  host_sources (
    host_id, host_type, host_name, host_description,
    host_set_id, host_set_type, host_set_name, host_set_description,
    host_catalog_id, host_catalog_type, host_catalog_name, host_catalog_description,
    target_id, target_type, target_name, target_description,
    target_default_port_number, target_session_max_seconds, target_session_connection_limit,
    project_id, project_name, project_description,
    organization_id, organization_name, organization_description
  ) as (
    select -- id is the first column in the target view
      h.public_id                     as host_id,
      case
        when sh.public_id is not null then 'static host'
        when ph.public_id is not null then 'plugin host'
        else 'Unknown'
      end                             as host_type,
      case
        when sh.public_id is not null then coalesce(sh.name, 'None')
        when ph.public_id is not null then coalesce(ph.name, 'None')
        else 'Unknown'
      end                             as host_name,
      case
        when sh.public_id is not null then coalesce(sh.description, 'None')
        when ph.public_id is not null then coalesce(ph.description, 'None')
        else 'Unknown'
      end                             as host_description,
      hs.public_id                    as host_set_id,
      case
        when shs.public_id is not null then 'static host set'
        when phs.public_id is not null then 'plugin host set'
        else 'Unknown'
      end                             as host_set_type,
      case
        when shs.public_id is not null then coalesce(shs.name, 'None')
        when phs.public_id is not null then coalesce(phs.name, 'None')
        else 'None'
      end                             as host_set_name,
      case
        when shs.public_id is not null then coalesce(shs.description, 'None')
        when phs.public_id is not null then coalesce(phs.description, 'None')
        else 'None'
      end                             as host_set_description,
      hc.public_id                    as host_catalog_id,
      case
        when shc.public_id is not null then 'static host catalog'
        when phc.public_id is not null then 'plugin host catalog'
        else 'Unknown'
      end                             as host_catalog_type,
      case
        when shc.public_id is not null then coalesce(shc.name, 'None')
        when phc.public_id is not null then coalesce(phc.name, 'None')
        else 'None'
      end                             as host_catalog_name,
      case
        when shc.public_id is not null then coalesce(shc.description, 'None')
        when phc.public_id is not null then coalesce(phc.description, 'None')
        else 'None'
      end                             as host_catalog_description,
      t.public_id                     as target_id,
      case
        when t.type = 'tcp' then 'tcp target'
        when t.type = 'ssh' then 'ssh target'
        when t.type = 'rdp' then 'rdp target'
        when t.type = 'kubernetes' then 'kubernetes target'
        else 'Unknown'
      end                             as target_type,
      coalesce(t.name, 'None')        as target_name,
      coalesce(t.description, 'None') as target_description,
      coalesce(t.default_port, 0)     as target_default_port_number,
      t.session_max_seconds           as target_session_max_seconds,
      t.session_connection_limit      as target_session_connection_limit,
      p.public_id                     as project_id,
      coalesce(p.name, 'None')        as project_name,
      coalesce(p.description, 'None') as project_description,
      o.public_id                     as organization_id,
      coalesce(o.name, 'None')        as organization_name,
      coalesce(o.description, 'None') as organization_description
    from host as h
      join host_catalog as hc                on h.catalog_id = hc.public_id
      join host_set as hs                    on h.catalog_id = hs.catalog_id
      join target_host_set as ts             on hs.public_id = ts.host_set_id
      join target_all_subtypes as t          on ts.target_id = t.public_id
      join iam_scope as p                    on t.project_id = p.public_id and p.type = 'project'
      join iam_scope as o                    on p.parent_id = o.public_id and o.type = 'org'

      left join static_host as sh            on sh.public_id = h.public_id
      left join host_plugin_host as ph       on ph.public_id = h.public_id
      left join static_host_catalog as shc   on shc.public_id = hc.public_id
      left join host_plugin_catalog as phc   on phc.public_id = hc.public_id
      left join static_host_set as shs       on shs.public_id = hs.public_id
      left join host_plugin_set as phs       on phs.public_id = hs.public_id
  ),
  host_target_address (
    host_id, host_type, host_name, host_description,
    host_set_id, host_set_type, host_set_name, host_set_description,
    host_catalog_id, host_catalog_type, host_catalog_name, host_catalog_description,
    target_id, target_type, target_name, target_description,
    target_default_port_number, target_session_max_seconds, target_session_connection_limit,
    project_id, project_name, project_description,
    organization_id, organization_name, organization_description
  ) as (
    select
      'Not Applicable'                as host_id,
      'direct address'                as host_type,
      'Not Applicable'                as host_name,
      'Not Applicable'                as host_description,
      'Not Applicable'                as host_set_id,
      'Not Applicable'                as host_set_type,
      'Not Applicable'                as host_set_name,
      'Not Applicable'                as host_set_description,
      'Not Applicable'                as host_catalog_id,
      'Not Applicable'                as host_catalog_type,
      'Not Applicable'                as host_catalog_name,
      'Not Applicable'                as host_catalog_description,
      t.public_id                     as target_id,
      case
        when t.type = 'tcp' then 'tcp target'
        when t.type = 'ssh' then 'ssh target'
        when t.type = 'rdp' then 'rdp target'
        when t.type = 'kubernetes' then 'kubernetes target'
        else 'Unknown'
      end                             as target_type,
      coalesce(t.name, 'None')        as target_name,
      coalesce(t.description, 'None') as target_description,
      coalesce(t.default_port, 0)     as target_default_port_number,
      t.session_max_seconds           as target_session_max_seconds,
      t.session_connection_limit      as target_session_connection_limit,
      p.public_id                     as project_id,
      coalesce(p.name, 'None')        as project_name,
      coalesce(p.description, 'None') as project_description,
      o.public_id                     as organization_id,
      coalesce(o.name, 'None')        as organization_name,
      coalesce(o.description, 'None') as organization_description
    from target_all_subtypes as t
      right join target_address as ta on t.public_id = ta.target_id
      left join iam_scope as p        on p.public_id = t.project_id
      left join iam_scope as o        on o.public_id = p.parent_id
  )
  select * from host_sources
  union
  select * from host_target_address;

  create view whx_credential_dimension_source as
    with vault_generic_library as (
      select vcl.public_id                                        as public_id,
             'vault generic credential library'                   as type,
             coalesce(vcl.name,        'None')                    as name,
             coalesce(vcl.description, 'None')                    as description,
             vcl.vault_path                                       as vault_path,
             vcl.http_method                                      as http_method,
             case
               when vcl.http_method = 'GET' then 'Not Applicable'
               else coalesce(vcl.http_request_body::text, 'None')
             end                                                  as http_request_body,
             'Not Applicable'                                     as username,
             'Not Applicable'                                     as key_type_and_bits
        from credential_vault_generic_library as vcl
    ),
    vault_ssh_cert_library as (
      select vsccl.public_id                                      as public_id,
             'vault ssh certificate credential library'           as type,
             coalesce(vsccl.name,        'None')                  as name,
             coalesce(vsccl.description, 'None')                  as description,
             vsccl.vault_path                                     as vault_path,
             'Not Applicable'                                     as http_method,
             'Not Applicable'                                     as http_request_body,
             vsccl.username                                       as username,
             case
               when vsccl.key_type = 'ed25519' then vsccl.key_type
               else vsccl.key_type || '-' || vsccl.key_bits::text
             end                                                  as key_type_and_bits
        from credential_vault_ssh_cert_library as vsccl
    ),
    vault_ldap_library as (
      select vldapcl.public_id                                    as public_id,
             'vault ldap credential library'                      as type,
             coalesce(vldapcl.name,        'None')                as name,
             coalesce(vldapcl.description, 'None')                as description,
             vldapcl.vault_path                                   as vault_path,
             'Not Applicable'                                     as http_method,
             'Not Applicable'                                     as http_request_body,
             'Not Applicable'                                     as username,
             'Not Applicable'                                     as key_type_and_bits
        from credential_vault_ldap_library as vldapcl
    ),
    final as (
          select s.public_id                                                                         as session_id,
                 scd.credential_purpose                                                              as credential_purpose,
                 cl.public_id                                                                        as credential_library_id,
                 coalesce(vcl.type,              vsccl.type,              vldapcl.type)              as credential_library_type,
                 coalesce(vcl.name,              vsccl.name,              vldapcl.name)              as credential_library_name,
                 coalesce(vcl.description,       vsccl.description,       vldapcl.description)       as credential_library_description,
                 coalesce(vcl.vault_path,        vsccl.vault_path,        vldapcl.vault_path)        as credential_library_vault_path,
                 coalesce(vcl.http_method,       vsccl.http_method,       vldapcl.http_method)       as credential_library_vault_http_method,
                 coalesce(vcl.http_request_body, vsccl.http_request_body, vldapcl.http_request_body) as credential_library_vault_http_request_body,
                 coalesce(vcl.username,          vsccl.username,          vldapcl.username)          as credential_library_username,
                 coalesce(vcl.key_type_and_bits, vsccl.key_type_and_bits, vldapcl.key_type_and_bits) as credential_library_key_type_and_bits,
                 cs.public_id                                                                        as credential_store_id,
                 case
                   when vcs is null then 'None'
                   else 'vault credential store'
                 end                                                                                 as credential_store_type,
                 coalesce(vcs.name,              'None')                                             as credential_store_name,
                 coalesce(vcs.description,       'None')                                             as credential_store_description,
                 coalesce(vcs.namespace,         'None')                                             as credential_store_vault_namespace,
                 coalesce(vcs.vault_address,     'None')                                             as credential_store_vault_address,
                 t.public_id                                                                         as target_id,
                 case
                   when tt.type = 'tcp' then 'tcp target'
                   when tt.type = 'ssh' then 'ssh target'
                   when tt.type = 'rdp' then 'rdp target'
                   when tt.type = 'kubernetes' then 'kubernetes target'
                   else 'Unknown'
                 end                                                                                 as target_type,
                 coalesce(tt.name,               'None')                                             as target_name,
                 coalesce(tt.description,        'None')                                             as target_description,
                 coalesce(tt.default_port,       0)                                                  as target_default_port_number,
                 tt.session_max_seconds                                                              as target_session_max_seconds,
                 tt.session_connection_limit                                                         as target_session_connection_limit,
                 p.public_id                                                                         as project_id,
                 coalesce(p.name,                'None')                                             as project_name,
                 coalesce(p.description,         'None')                                             as project_description,
                 o.public_id                                                                         as organization_id,
                 coalesce(o.name,                'None')                                             as organization_name,
                 coalesce(o.description,         'None')                                             as organization_description
            from session_credential_dynamic as scd
            join session                    as s       on scd.session_id = s.public_id
            join credential_library         as cl      on scd.library_id = cl.public_id
            join credential_store           as cs      on cl.store_id    = cs.public_id
            join target                     as t       on s.target_id    = t.public_id
            join iam_scope                  as p       on p.public_id    = t.project_id and p.type = 'project'
            join iam_scope                  as o       on p.parent_id    = o.public_id  and o.type = 'org'
       left join vault_generic_library      as vcl     on cl.public_id   = vcl.public_id
       left join vault_ssh_cert_library     as vsccl   on cl.public_id   = vsccl.public_id
       left join vault_ldap_library         as vldapcl on cl.public_id   = vldapcl.public_id
       left join credential_vault_store     as vcs     on cs.public_id   = vcs.public_id
       left join target_all_subtypes        as tt      on t.public_id    = tt.public_id
    )
    select session_id,
           credential_purpose,
           credential_library_id,
           credential_library_type,
           credential_library_name,
           credential_library_description,
           credential_library_vault_path,
           credential_library_vault_http_method,
           credential_library_vault_http_request_body,
           credential_library_username,
           credential_library_key_type_and_bits,
           credential_store_id,
           credential_store_type,
           credential_store_name,
           credential_store_description,
           credential_store_vault_namespace,
           credential_store_vault_address,
           target_id,
           target_type,
           target_name,
           target_description,
           target_default_port_number,
           target_session_max_seconds,
           target_session_connection_limit,
           project_id,
           project_name,
           project_description,
           organization_id,
           organization_name,
           organization_description
      from final;

commit;
