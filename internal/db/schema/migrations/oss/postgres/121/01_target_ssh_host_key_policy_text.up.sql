-- Copyright Boundary Unlimited contributors 2026
-- SPDX-License-Identifier: MIT

begin;
  -- The ssh host key policy is stored as one bounded text value per list: the
  -- authorized_keys entries joined with newlines. No valid entry can contain a
  -- newline. This replaces the text[] columns of migration 119 and carries
  -- over any existing rows.
  alter table target_ssh
    drop constraint host_key_policy_keys_count_limit,
    drop constraint host_key_policy_keys_size_limit,
    drop constraint host_key_policy_cas_count_limit,
    drop constraint host_key_policy_cas_size_limit,
    alter column host_key_policy_keys drop default,
    alter column host_key_policy_cas drop default;

  alter table target_ssh
    alter column host_key_policy_keys type text using array_to_string(host_key_policy_keys, E'\n'),
    alter column host_key_policy_cas type text using array_to_string(host_key_policy_cas, E'\n');

  alter table target_ssh
    alter column host_key_policy_keys set default '',
    alter column host_key_policy_cas set default '',
    add constraint host_key_policy_keys_count_limit
      check(cardinality(string_to_array(host_key_policy_keys, E'\n')) <= 16),
    add constraint host_key_policy_keys_size_limit
      check(octet_length(host_key_policy_keys) <= 65551),
    add constraint host_key_policy_cas_count_limit
      check(cardinality(string_to_array(host_key_policy_cas, E'\n')) <= 16),
    add constraint host_key_policy_cas_size_limit
      check(octet_length(host_key_policy_cas) <= 65551);

  alter table target_ssh_hst
    alter column host_key_policy_keys drop default,
    alter column host_key_policy_cas drop default;

  alter table target_ssh_hst
    alter column host_key_policy_keys type text using array_to_string(host_key_policy_keys, E'\n'),
    alter column host_key_policy_cas type text using array_to_string(host_key_policy_cas, E'\n');

  alter table target_ssh_hst
    alter column host_key_policy_keys set default '',
    alter column host_key_policy_cas set default '';

  comment on column target_ssh.host_key_policy_keys is
    'host_key_policy_keys are the pinned upstream host public keys in authorized_keys format, one per line.';
  comment on column target_ssh.host_key_policy_cas is
    'host_key_policy_cas are the trusted upstream host CA public keys in authorized_keys format, one per line.';

  -- target_all_subtypes is recreated with the policy columns so that every
  -- target lookup reads them back; without them a stored policy would read as
  -- empty.

  -- The whx_* views here depend on target_all_subtypes, so we need to drop
  -- these first.
  drop view whx_host_dimension_source;
  drop view whx_credential_dimension_source;
  drop view target_all_subtypes;

  -- replaces target_all_subtypes defined in 113/01_kubernetes_targets.up.sql
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
    '' as host_key_policy_keys,
    '' as host_key_policy_cas,
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
    host_key_policy_keys,
    host_key_policy_cas,
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
    '' as host_key_policy_keys,
    '' as host_key_policy_cas,
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
    '' as host_key_policy_keys,
    '' as host_key_policy_cas,
    'kubernetes' as type
  from
    target_kubernetes;

  -- replaces whx_host_dimension_source defined in 113/01_kubernetes_targets.up.sql
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
