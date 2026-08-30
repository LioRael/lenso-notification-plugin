use lenso_postgres_kit::{
    OwnedPostgres, PostgresKitError, SchemaOperator, SetupOutcome, UpgradeOutcome,
};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::PgPoolOptions;
use thiserror::Error;

use crate::migrations::{NOTIFICATION_MIGRATIONS, schema_plan};

const LEGACY_SCHEMA_PREFIX: &str = "create schema if not exists notification;";
const LEGACY_HOST_MIGRATION_NAME: &str = "notification/0001_create_notification_schema";
const GLOBAL_MAINTENANCE_LOCK_SQL: &str =
    "select pg_advisory_xact_lock(hashtextextended(current_database() || ':lenso-maintenance', 0))";
const NOTIFICATION_OPERATOR_LOCK_SQL: &str =
    "select pg_advisory_xact_lock(hashtextextended(current_database() || ':notification', 0))";
const MANAGED_LEDGER_REFERENCE_SQL: &str = r#"
create table pg_temp._lenso_schema_migrations (
    version bigint primary key check (version > 0),
    name text not null,
    checksum text not null,
    applied_at timestamptz not null default transaction_timestamp()
);
"#;
const LEGACY_TABLES: &[&str] = &[
    "attempts",
    "consumed_events",
    "deliveries",
    "intents",
    "receipts",
    "render_snapshots",
    "retry_requests",
    "source_lifecycle_events",
    "template_releases",
];
const LEGACY_LOCK_SQL: &str = r#"
lock table platform.schema_migrations in share mode;
lock table notification.attempts,
           notification.consumed_events,
           notification.deliveries,
           notification.intents,
           notification.receipts,
           notification.render_snapshots,
           notification.retry_requests,
           notification.source_lifecycle_events,
           notification.template_releases
    in access exclusive mode;
"#;

/// Explicit schema administration for one Notification Plugin Instance.
#[derive(Clone, Debug)]
pub struct NotificationOperator {
    postgres: OwnedPostgres,
}

impl NotificationOperator {
    pub async fn setup(database_url: &str) -> Result<SetupOutcome, NotificationOperatorError> {
        Ok(
            SchemaOperator::connect(database_url, schema_plan("notification")?)
                .await?
                .setup()
                .await?,
        )
    }

    pub async fn upgrade(database_url: &str) -> Result<UpgradeOutcome, NotificationOperatorError> {
        Ok(
            SchemaOperator::connect(database_url, schema_plan("notification")?)
                .await?
                .upgrade()
                .await?,
        )
    }

    /// One-time, fail-closed adoption of the exact pre-Plugin Notification
    /// schema. This records migration 1 without rewriting any ledger rows or
    /// replaying the immutable legacy SQL against the owned schema. Adoption
    /// is a mandatory maintenance-window operation: all Notification writers
    /// and DDL actors must be stopped. It locks the shared legacy ledger in
    /// share mode and all legacy Notification tables in access-exclusive mode
    /// until the catalog proof and Plugin migration record commit. The advisory
    /// shared maintenance advisory lock coordinates cooperating schema
    /// operators, followed by the Notification-specific advisory lock.
    /// `PostgreSQL` has no schema namespace lock here, so these locks do not make
    /// arbitrary concurrent `CREATE` statements atomic with adoption.
    pub async fn adopt_legacy(
        database_url: &str,
    ) -> Result<LegacyAdoptionOutcome, NotificationOperatorError> {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(database_url)
            .await?;
        let mut transaction = pool.begin().await?;
        // All adopting operators take the shared maintenance key first. This
        // ordering prevents cross-schema operator deadlocks; direct owner DDL
        // remains outside the protocol and must be quiesced by the operator.
        sqlx::query(GLOBAL_MAINTENANCE_LOCK_SQL)
            .execute(transaction.as_mut())
            .await?;
        sqlx::query(NOTIFICATION_OPERATOR_LOCK_SQL)
            .execute(transaction.as_mut())
            .await?;

        let owner: Option<String> = sqlx::query_scalar(
            r#"
            select roles.rolname::text
            from pg_namespace namespaces
            join pg_roles roles on roles.oid = namespaces.nspowner
            where namespaces.nspname = 'notification'
            "#,
        )
        .fetch_optional(transaction.as_mut())
        .await?;
        let Some(owner) = owner else {
            return Err(NotificationOperatorError::LegacySchemaMissing);
        };
        let current_role: String = sqlx::query_scalar("select current_user::text")
            .fetch_one(transaction.as_mut())
            .await?;
        if owner != current_role {
            return Err(NotificationOperatorError::LegacyOwnershipMismatch {
                owner,
                current_role,
            });
        }
        if unsafe_owner_default_acl(transaction.as_mut()).await? {
            return Err(NotificationOperatorError::LegacySchemaMismatch);
        }
        if unsafe_publication_scope(transaction.as_mut(), "notification").await?
            || unsafe_publication_scope(transaction.as_mut(), "platform").await?
        {
            return Err(NotificationOperatorError::LegacySchemaMismatch);
        }
        let managed: bool = sqlx::query_scalar(
            r#"
            select exists (
                select 1
                from pg_class relations
                join pg_namespace namespaces on namespaces.oid = relations.relnamespace
                where namespaces.nspname = 'notification'
                  and relations.relname = '_lenso_schema_migrations'
                  and relations.relkind = 'r'
            )
            "#,
        )
        .fetch_one(transaction.as_mut())
        .await?;
        if managed {
            return Err(NotificationOperatorError::LegacySchemaAlreadyManaged);
        }
        let (host_ledger_exists, target_tables_match) =
            legacy_lock_targets_exist(transaction.as_mut()).await?;
        if !host_ledger_exists {
            return Err(NotificationOperatorError::LegacyHostLedgerMismatch);
        }
        if !target_tables_match {
            return Err(NotificationOperatorError::LegacySchemaMismatch);
        }
        sqlx::raw_sql(LEGACY_LOCK_SQL)
            .execute(transaction.as_mut())
            .await?;
        if !legacy_host_ledger_matches(transaction.as_mut()).await? {
            return Err(NotificationOperatorError::LegacyHostLedgerMismatch);
        }
        if !legacy_schema_matches(transaction.as_mut()).await? {
            return Err(NotificationOperatorError::LegacySchemaMismatch);
        }

        sqlx::query(
            r#"
            create table notification._lenso_schema_migrations (
                version bigint primary key check (version > 0),
                name text not null,
                checksum text not null,
                applied_at timestamptz not null default transaction_timestamp()
            )
            "#,
        )
        .execute(transaction.as_mut())
        .await?;
        if !plugin_ledger_is_private(transaction.as_mut()).await? {
            return Err(NotificationOperatorError::LegacySchemaMismatch);
        }
        let migration = &NOTIFICATION_MIGRATIONS[0];
        sqlx::query(
            "insert into notification._lenso_schema_migrations (version, name, checksum) values ($1, $2, $3)",
        )
        .bind(i64::try_from(migration.version()).expect("migration version fits bigint"))
        .bind(migration.name())
        .bind(migration_checksum(migration))
        .execute(transaction.as_mut())
        .await?;
        if unsafe_owner_default_acl(transaction.as_mut()).await?
            || unsafe_publication_scope(transaction.as_mut(), "notification").await?
            || unsafe_publication_scope(transaction.as_mut(), "platform").await?
            || !managed_schema_matches_existing_reference(transaction.as_mut()).await?
        {
            return Err(NotificationOperatorError::LegacySchemaMismatch);
        }
        transaction.commit().await?;
        pool.close().await;
        Ok(LegacyAdoptionOutcome { version: 1 })
    }

    pub async fn connect(database_url: &str) -> Result<Self, NotificationOperatorError> {
        let postgres = OwnedPostgres::prepare(database_url, schema_plan("notification")?).await?;
        verify_managed_catalog(postgres.pool()).await?;
        Ok(Self { postgres })
    }

    pub fn schema(&self) -> &str {
        self.postgres.schema()
    }
}

async fn unsafe_owner_default_acl(
    connection: &mut sqlx::PgConnection,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        select exists (
            select 1
            from pg_default_acl defaults
            join pg_roles roles on roles.oid = defaults.defaclrole
            left join pg_namespace namespaces on namespaces.oid = defaults.defaclnamespace
            where roles.rolname = current_user
              and (
                  defaults.defaclnamespace = 0
                  or namespaces.nspname in ('notification', 'platform')
              )
        )
        "#,
    )
    .fetch_one(&mut *connection)
    .await
}

async fn unsafe_publication_scope(
    connection: &mut sqlx::PgConnection,
    schema: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        select exists (
            select 1 from pg_publication publications
            where publications.puballtables
        ) or exists (
            select 1
            from pg_publication_namespace memberships
            join pg_namespace namespaces on namespaces.oid = memberships.pnnspid
            where namespaces.nspname = $1
        )
        "#,
    )
    .bind(schema)
    .fetch_one(&mut *connection)
    .await
}

async fn unsupported_schema_object_count(
    connection: &mut sqlx::PgConnection,
    schema: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        select
              (select count(*) from pg_collation objects where objects.collnamespace = namespaces.oid)
            + (select count(*) from pg_conversion objects where objects.connamespace = namespaces.oid)
            + (select count(*) from pg_operator objects where objects.oprnamespace = namespaces.oid)
            + (select count(*) from pg_opclass objects where objects.opcnamespace = namespaces.oid)
            + (select count(*) from pg_opfamily objects where objects.opfnamespace = namespaces.oid)
            + (select count(*) from pg_statistic_ext objects where objects.stxnamespace = namespaces.oid)
            + (select count(*) from pg_ts_config objects where objects.cfgnamespace = namespaces.oid)
            + (select count(*) from pg_ts_dict objects where objects.dictnamespace = namespaces.oid)
            + (select count(*) from pg_ts_parser objects where objects.prsnamespace = namespaces.oid)
            + (select count(*) from pg_ts_template objects where objects.tmplnamespace = namespaces.oid)
            + (select count(*) from pg_extension objects where objects.extnamespace = namespaces.oid)
            + (select count(*) from pg_constraint objects
               where objects.connamespace = namespaces.oid and objects.conrelid = 0)
        from pg_namespace namespaces
        where namespaces.nspname = $1
        "#,
    )
    .bind(schema)
    .fetch_one(&mut *connection)
    .await
}

pub(crate) async fn verify_managed_catalog(
    pool: &sqlx::PgPool,
) -> Result<(), NotificationOperatorError> {
    let mut connection = pool.acquire().await?;
    if unsafe_owner_default_acl(&mut connection).await?
        || !managed_schema_matches(&mut connection).await?
    {
        return Err(NotificationOperatorError::ManagedSchemaMismatch);
    }
    Ok(())
}

async fn plugin_ledger_is_private(
    connection: &mut sqlx::PgConnection,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        select relations.relkind = 'r'
           and pg_get_userbyid(relations.relowner) = current_user
           and relations.relacl is null
           and not exists (
               select 1
               from pg_attribute attributes
               where attributes.attrelid = relations.oid
                 and attributes.attnum > 0
                 and not attributes.attisdropped
                 and attributes.attacl is not null
           )
        from pg_class relations
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        where namespaces.nspname = 'notification'
          and relations.relname = '_lenso_schema_migrations'
        "#,
    )
    .fetch_one(&mut *connection)
    .await
}

async fn legacy_lock_targets_exist(
    connection: &mut sqlx::PgConnection,
) -> Result<(bool, bool), sqlx::Error> {
    let host_ledger_exists: bool = sqlx::query_scalar(
        r#"
        select exists (
            select 1
            from pg_class relations
            join pg_namespace namespaces on namespaces.oid = relations.relnamespace
            where namespaces.nspname = 'platform'
              and relations.relname = 'schema_migrations'
              and relations.relkind = 'r'
        )
        "#,
    )
    .fetch_one(&mut *connection)
    .await?;
    let target_tables = sqlx::query_scalar::<_, String>(
        r#"
        select relations.relname::text
        from pg_class relations
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        where namespaces.nspname = 'notification'
          and relations.relkind = 'r'
        order by relations.relname
        "#,
    )
    .fetch_all(&mut *connection)
    .await?;
    Ok((
        host_ledger_exists,
        target_tables
            == LEGACY_TABLES
                .iter()
                .map(|table| (*table).to_owned())
                .collect::<Vec<_>>(),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyAdoptionOutcome {
    pub version: u64,
}

#[derive(Debug, Error)]
pub enum NotificationOperatorError {
    #[error(transparent)]
    Plan(#[from] lenso_postgres_kit::PlanError),
    #[error(transparent)]
    Postgres(#[from] PostgresKitError),
    #[error("legacy Notification schema does not exist")]
    LegacySchemaMissing,
    #[error("Notification schema is already managed; use setup or upgrade")]
    LegacySchemaAlreadyManaged,
    #[error("legacy Notification schema does not match the immutable v1 fingerprint")]
    LegacySchemaMismatch,
    #[error("managed Notification schema does not match the exact Plugin catalog fingerprint")]
    ManagedSchemaMismatch,
    #[error("legacy Host migration ledger does not prove the Notification v1 migration")]
    LegacyHostLedgerMismatch,
    #[error("legacy Notification schema is owned by `{owner}`, not current role `{current_role}`")]
    LegacyOwnershipMismatch { owner: String, current_role: String },
    #[error("legacy Notification schema adoption failed")]
    Database(#[from] sqlx::Error),
}

async fn legacy_schema_matches(connection: &mut sqlx::PgConnection) -> Result<bool, sqlx::Error> {
    if unsafe_publication_scope(connection, "notification").await?
        || unsupported_schema_object_count(connection, "notification").await? != 0
    {
        return Ok(false);
    }
    let actual = legacy_schema_fingerprint(connection, "notification").await?;
    let Some(reference_sql) = legacy_reference_sql() else {
        return Ok(false);
    };
    // Audited source: this string is derived only from the immutable, compiled-in v1
    // migration and substitutes a fixed `pg_temp` qualifier. It contains no caller input.
    sqlx::raw_sql(sqlx::AssertSqlSafe(reference_sql))
        .execute(&mut *connection)
        .await?;
    let reference_schema: String = sqlx::query_scalar(
        r#"
        select namespaces.nspname::text
        from pg_namespace namespaces
        where namespaces.oid = pg_my_temp_schema()
        "#,
    )
    .fetch_one(&mut *connection)
    .await?;
    let expected = legacy_schema_fingerprint(connection, &reference_schema).await?;
    let actual = actual.normalized("notification");
    let expected = expected.normalized(&reference_schema);
    Ok(actual == expected)
}

async fn managed_schema_matches(connection: &mut sqlx::PgConnection) -> Result<bool, sqlx::Error> {
    // Runtime pools are fresh, but clearing connection-local temporary objects
    // keeps repeated operator verification deterministic on a reused connection.
    sqlx::query("discard temp")
        .execute(&mut *connection)
        .await?;
    let Some(reference_sql) = managed_reference_sql() else {
        return Ok(false);
    };
    sqlx::raw_sql(sqlx::AssertSqlSafe(reference_sql))
        .execute(&mut *connection)
        .await?;
    managed_schema_matches_existing_reference(connection).await
}

async fn managed_schema_matches_existing_reference(
    connection: &mut sqlx::PgConnection,
) -> Result<bool, sqlx::Error> {
    if unsafe_publication_scope(connection, "notification").await?
        || unsupported_schema_object_count(connection, "notification").await? != 0
    {
        return Ok(false);
    }
    let actual = legacy_schema_fingerprint(connection, "notification").await?;
    sqlx::raw_sql(MANAGED_LEDGER_REFERENCE_SQL)
        .execute(&mut *connection)
        .await?;
    let reference_schema: String = sqlx::query_scalar(
        r#"
        select namespaces.nspname::text
        from pg_namespace namespaces
        where namespaces.oid = pg_my_temp_schema()
        "#,
    )
    .fetch_one(&mut *connection)
    .await?;
    let expected = legacy_schema_fingerprint(connection, &reference_schema).await?;
    Ok(actual.normalized("notification") == expected.normalized(&reference_schema))
}

async fn legacy_host_ledger_matches(
    connection: &mut sqlx::PgConnection,
) -> Result<bool, sqlx::Error> {
    if unsafe_publication_scope(connection, "platform").await? {
        return Ok(false);
    }
    let relation = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            bool,
            bool,
            String,
            String,
            String,
            bool,
            String,
            String,
            Option<String>,
        ),
    >(
        r#"
        select relations.relkind::text,
               pg_get_userbyid(namespaces.nspowner)::text,
               pg_get_userbyid(relations.relowner)::text,
               namespaces.nspacl::text,
               relations.relacl::text,
               relations.relrowsecurity,
               relations.relforcerowsecurity,
               relations.relpersistence::text,
               access_methods.amname::text,
               coalesce((
                   select jsonb_agg(option order by option)::text
                   from unnest(relations.reloptions) option
               ), '[]'),
               relations.relispartition,
               relations.relreplident::text,
               coalesce(tablespaces.spcname::text, ''),
               obj_description(relations.oid, 'pg_class')::text
        from pg_class relations
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        left join pg_am access_methods on access_methods.oid = relations.relam
        left join pg_tablespace tablespaces on tablespaces.oid = relations.reltablespace
        where namespaces.nspname = 'platform'
          and relations.relname = 'schema_migrations'
        "#,
    )
    .fetch_optional(&mut *connection)
    .await?;
    let current_role: String = sqlx::query_scalar("select current_user::text")
        .fetch_one(&mut *connection)
        .await?;
    let Some((
        relation_kind,
        schema_owner,
        table_owner,
        schema_acl,
        table_acl,
        row_security,
        force_row_security,
        persistence,
        access_method,
        relation_options,
        is_partition,
        replica_identity,
        tablespace,
        comment,
    )) = relation
    else {
        return Ok(false);
    };
    if relation_kind != "r"
        || schema_owner != current_role
        || table_owner != current_role
        || schema_acl.is_some()
        || table_acl.is_some()
        || row_security
        || force_row_security
        || persistence != "p"
        || access_method != "heap"
        || relation_options != "[]"
        || is_partition
        || replica_identity != "d"
        || !tablespace.is_empty()
        || comment.is_some()
    {
        return Ok(false);
    }

    let columns = sqlx::query_scalar::<_, sqlx::types::Json<serde_json::Value>>(
        r#"
        select jsonb_build_array(
               attributes.attnum,
               attributes.attname,
               format_type(attributes.atttypid, attributes.atttypmod),
               attributes.attnotnull,
               coalesce(pg_get_expr(defaults.adbin, defaults.adrelid, false), ''),
               attributes.attidentity::text,
               attributes.attgenerated::text,
               attributes.attndims,
               attributes.attislocal,
               attributes.attinhcount,
               attributes.atthasmissing,
               coalesce(attributes.attmissingval::text, ''),
               attributes.attstorage::text,
               attributes.attcompression::text,
               coalesce(attributes.attstattarget, -1),
               coalesce((
                   select jsonb_agg(option order by option)
                   from unnest(attributes.attoptions) option
               ), '[]'::jsonb),
               coalesce((
                   select jsonb_agg(option order by option)
                   from unnest(attributes.attfdwoptions) option
               ), '[]'::jsonb),
               coalesce(collations.collname, ''),
               coalesce(attributes.attacl::text, ''),
               coalesce(col_description(relations.oid, attributes.attnum), '')
        )
        from pg_attribute attributes
        join pg_class relations on relations.oid = attributes.attrelid
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        left join pg_attrdef defaults
          on defaults.adrelid = relations.oid and defaults.adnum = attributes.attnum
        left join pg_collation collations on collations.oid = attributes.attcollation
        where namespaces.nspname = 'platform'
          and relations.relname = 'schema_migrations'
          and attributes.attnum > 0
          and not attributes.attisdropped
        order by attributes.attnum
        "#,
    )
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .map(|value| value.0)
    .collect::<Vec<_>>();
    let expected_columns = vec![
        serde_json::json!([
            1,
            "name",
            "text",
            true,
            "",
            "",
            "",
            0,
            true,
            0,
            false,
            "",
            "x",
            "",
            -1,
            [],
            [],
            "default",
            "",
            ""
        ]),
        serde_json::json!([
            2,
            "applied_at",
            "timestamp with time zone",
            true,
            "now()",
            "",
            "",
            0,
            true,
            0,
            false,
            "",
            "p",
            "",
            -1,
            [],
            [],
            "",
            "",
            ""
        ]),
    ];
    if columns != expected_columns {
        return Ok(false);
    }

    let relation_types = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        r#"
        with ledger as (
            select relations.reltype
            from pg_class relations
            join pg_namespace namespaces on namespaces.oid = relations.relnamespace
            where namespaces.nspname = 'platform'
              and relations.relname = 'schema_migrations'
        ), ledger_types as (
            select composite_types.oid
            from pg_type composite_types, ledger
            where composite_types.oid = ledger.reltype
            union all
            select composite_types.typarray
            from pg_type composite_types, ledger
            where composite_types.oid = ledger.reltype
        )
        select types.typname::text,
               pg_get_userbyid(types.typowner)::text,
               types.typacl::text,
               obj_description(types.oid, 'pg_type')::text
        from pg_type types
        join ledger_types on ledger_types.oid = types.oid
        order by types.typname
        "#,
    )
    .fetch_all(&mut *connection)
    .await?;
    if relation_types
        != vec![
            (
                "_schema_migrations".to_owned(),
                current_role.clone(),
                None,
                None,
            ),
            (
                "schema_migrations".to_owned(),
                current_role.clone(),
                None,
                None,
            ),
        ]
    {
        return Ok(false);
    }

    let constraints = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            bool,
            bool,
            bool,
            bool,
            Option<String>,
        ),
    >(
        r#"
        select constraints.conname::text,
               constraints.contype::text,
               pg_get_constraintdef(constraints.oid, false)::text,
               constraints.condeferrable,
               constraints.condeferred,
               constraints.convalidated,
               constraints.connoinherit,
               obj_description(constraints.oid, 'pg_constraint')::text
        from pg_constraint constraints
        join pg_class relations on relations.oid = constraints.conrelid
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        where namespaces.nspname = 'platform'
          and relations.relname = 'schema_migrations'
          and constraints.contype <> 'n'
        order by constraints.conname
        "#,
    )
    .fetch_all(&mut *connection)
    .await?;
    if constraints
        != vec![(
            "schema_migrations_pkey".to_owned(),
            "p".to_owned(),
            "PRIMARY KEY (name)".to_owned(),
            false,
            false,
            true,
            true,
            None,
        )]
    {
        return Ok(false);
    }

    let indexes = sqlx::query_scalar::<_, sqlx::types::Json<serde_json::Value>>(
        r#"
        select jsonb_build_array(
               indexes.relname,
               catalog.indisunique,
               catalog.indisprimary,
               catalog.indisexclusion,
               catalog.indimmediate,
               catalog.indisvalid,
               catalog.indisready,
               catalog.indislive,
               catalog.indisreplident,
               catalog.indcheckxmin,
               indexes.relpersistence::text,
               pg_get_userbyid(indexes.relowner),
               access_methods.amname,
               coalesce((
                   select jsonb_agg(option order by option)
                   from unnest(indexes.reloptions) option
               ), '[]'::jsonb),
               coalesce(tablespaces.spcname, ''),
               coalesce(indexes.relacl::text, ''),
               coalesce(obj_description(indexes.oid, 'pg_class'), ''),
               pg_get_indexdef(indexes.oid, 0, false)
        )
        from pg_index catalog
        join pg_class indexes on indexes.oid = catalog.indexrelid
        join pg_class relations on relations.oid = catalog.indrelid
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        join pg_am access_methods on access_methods.oid = indexes.relam
        left join pg_tablespace tablespaces on tablespaces.oid = indexes.reltablespace
        where namespaces.nspname = 'platform'
          and relations.relname = 'schema_migrations'
        order by indexes.relname
        "#,
    )
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .map(|value| value.0)
    .collect::<Vec<_>>();
    if indexes
        != vec![serde_json::json!([
            "schema_migrations_pkey",
            true,
            true,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            "p",
            current_role,
            "btree",
            [],
            "",
            "",
            "",
            "CREATE UNIQUE INDEX schema_migrations_pkey ON platform.schema_migrations USING btree (name)"
        ])]
    {
        return Ok(false);
    }

    let has_extras: bool = sqlx::query_scalar(
        r#"
        with ledger as (
            select relations.oid, relations.reltype
            from pg_class relations
            join pg_namespace namespaces on namespaces.oid = relations.relnamespace
            where namespaces.nspname = 'platform'
              and relations.relname = 'schema_migrations'
        )
        select exists (
            select 1 from pg_trigger triggers, ledger
            where triggers.tgrelid = ledger.oid and not triggers.tgisinternal
        ) or exists (
            select 1 from pg_policy policies, ledger
            where policies.polrelid = ledger.oid
        ) or exists (
            select 1 from pg_rewrite rules, ledger
            where rules.ev_class = ledger.oid and rules.rulename <> '_RETURN'
        ) or exists (
            select 1 from pg_seclabel labels, ledger
            where labels.classoid = 'pg_class'::regclass and labels.objoid = ledger.oid
        ) or exists (
            select 1
            from pg_seclabel labels, ledger
            join pg_type composite_types on composite_types.oid = ledger.reltype
            where labels.classoid = 'pg_type'::regclass
              and labels.objoid in (composite_types.oid, composite_types.typarray)
        ) or exists (
            select 1 from pg_publication_rel memberships, ledger
            where memberships.prrelid = ledger.oid
        ) or exists (
            select 1 from pg_inherits inheritance, ledger
            where inheritance.inhrelid = ledger.oid or inheritance.inhparent = ledger.oid
        )
        "#,
    )
    .fetch_one(&mut *connection)
    .await?;
    if has_extras {
        return Ok(false);
    }

    sqlx::query_scalar("select exists(select 1 from platform.schema_migrations where name = $1)")
        .bind(LEGACY_HOST_MIGRATION_NAME)
        .fetch_one(&mut *connection)
        .await
}

fn legacy_reference_sql() -> Option<String> {
    NOTIFICATION_MIGRATIONS[0]
        .sql()
        .strip_prefix(LEGACY_SCHEMA_PREFIX)
        .map(|body| body.replace("notification.", "pg_temp."))
}

fn managed_reference_sql() -> Option<String> {
    let mut reference = legacy_reference_sql()?;
    for migration in &NOTIFICATION_MIGRATIONS[1..] {
        reference.push('\n');
        reference.push_str(&migration.sql().replace("notification.", "pg_temp."));
    }
    Some(reference)
}

#[derive(Debug, Eq, PartialEq)]
struct LegacySchemaFingerprint {
    schema: String,
    relations: Vec<String>,
    columns: Vec<String>,
    constraints: Vec<String>,
    indexes: Vec<String>,
    triggers: Vec<String>,
    types: Vec<String>,
    routines: Vec<String>,
    policies: Vec<String>,
    inheritance: Vec<String>,
    rules: Vec<String>,
    security_labels: Vec<String>,
    publication_memberships: Vec<String>,
}

impl LegacySchemaFingerprint {
    fn normalized(mut self, schema: &str) -> Self {
        normalize_sql_fields(&mut self.columns, &[3, 5], schema);
        normalize_sql_fields(&mut self.constraints, &[7], schema);
        normalize_sql_fields(&mut self.indexes, &[18], schema);
        normalize_sql_fields(&mut self.triggers, &[3], schema);
        normalize_sql_fields(&mut self.routines, &[1, 10], schema);
        normalize_sql_fields(&mut self.policies, &[5, 6], schema);
        normalize_schema_name_fields(&mut self.inheritance, &[0, 2], schema);
        normalize_sql_fields(&mut self.rules, &[3], schema);
        normalize_sql_fields(&mut self.publication_memberships, &[2], schema);
        self
    }
}

fn normalize_sql_fields(rows: &mut [String], fields: &[usize], schema: &str) {
    for row in rows {
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(row) else {
            continue;
        };
        let Some(values) = value.as_array_mut() else {
            continue;
        };
        for field in fields {
            let Some(value) = values.get_mut(*field) else {
                continue;
            };
            let Some(sql) = value.as_str() else {
                continue;
            };
            *value = serde_json::Value::String(normalize_sql_qualifiers(sql, schema));
        }
        if let Ok(normalized) = serde_json::to_string(&value) {
            *row = normalized;
        }
    }
}

fn normalize_schema_name_fields(rows: &mut [String], fields: &[usize], schema: &str) {
    for row in rows {
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(row) else {
            continue;
        };
        let Some(values) = value.as_array_mut() else {
            continue;
        };
        for field in fields {
            let Some(value) = values.get_mut(*field) else {
                continue;
            };
            if value.as_str() == Some(schema) {
                *value = serde_json::Value::String("__lenso_owned_schema__".to_owned());
            }
        }
        if let Ok(normalized) = serde_json::to_string(&value) {
            *row = normalized;
        }
    }
}

fn normalize_sql_qualifiers(sql: &str, schema: &str) -> String {
    let mut qualifiers = vec![format!("{schema}."), format!("\"{schema}\".")];
    if schema.starts_with("pg_temp_") {
        qualifiers.push("pg_temp.".to_owned());
        qualifiers.push("\"pg_temp\".".to_owned());
    }
    let bytes = sql.as_bytes();
    let mut normalized = String::with_capacity(sql.len());
    let mut index = 0;
    let mut quote: Option<String> = None;

    while index < bytes.len() {
        if let Some(delimiter) = quote.as_deref() {
            if delimiter == "'" {
                let character = sql[index..].chars().next().expect("valid SQL character");
                normalized.push(character);
                index += character.len_utf8();
                if character == '\\' && index < bytes.len() {
                    let escaped = sql[index..]
                        .chars()
                        .next()
                        .expect("valid escaped SQL character");
                    normalized.push(escaped);
                    index += escaped.len_utf8();
                } else if character == '\'' {
                    if sql[index..].starts_with('\'') {
                        normalized.push('\'');
                        index += 1;
                    } else {
                        quote = None;
                    }
                }
                continue;
            }
            if sql[index..].starts_with(delimiter) {
                normalized.push_str(delimiter);
                index += delimiter.len();
                quote = None;
            } else {
                let character = sql[index..].chars().next().expect("valid SQL character");
                normalized.push(character);
                index += character.len_utf8();
            }
            continue;
        }

        if sql[index..].starts_with('\'') {
            normalized.push('\'');
            index += 1;
            quote = Some("'".to_owned());
            continue;
        }
        if let Some(delimiter) = dollar_quote_delimiter(&sql[index..]) {
            normalized.push_str(delimiter);
            index += delimiter.len();
            quote = Some(delimiter.to_owned());
            continue;
        }
        let token_boundary = index == 0
            || !matches!(bytes[index - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$');
        if let Some(qualifier) = token_boundary
            .then(|| {
                qualifiers
                    .iter()
                    .find(|qualifier| sql[index..].starts_with(qualifier.as_str()))
            })
            .flatten()
        {
            index += qualifier.len();
            continue;
        }
        if sql[index..].starts_with('"') {
            normalized.push('"');
            index += 1;
            quote = Some("\"".to_owned());
            continue;
        }
        let character = sql[index..].chars().next().expect("valid SQL character");
        normalized.push(character);
        index += character.len_utf8();
    }
    normalized
}

fn dollar_quote_delimiter(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'$') {
        return None;
    }
    let end = bytes[1..].iter().position(|byte| *byte == b'$')? + 1;
    let tag = &bytes[1..end];
    if tag.is_empty()
        || (tag[0].is_ascii_alphabetic() || tag[0] == b'_')
            && tag[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        Some(&value[..=end])
    } else {
        None
    }
}

async fn legacy_schema_fingerprint(
    connection: &mut sqlx::PgConnection,
    schema: &str,
) -> Result<LegacySchemaFingerprint, sqlx::Error> {
    let schema_fingerprint = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            pg_get_userbyid(namespaces.nspowner),
            coalesce(namespaces.nspacl::text, ''),
            coalesce(obj_description(namespaces.oid, 'pg_namespace'), '')
        )::text
        from pg_namespace namespaces
        where namespaces.nspname = $1
        "#,
    )
    .bind(schema)
    .fetch_one(&mut *connection)
    .await?;

    let relations = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            relations.relname,
            relations.relkind::text,
            pg_get_userbyid(relations.relowner),
            coalesce(relations.relacl::text, ''),
            relations.relrowsecurity,
            relations.relforcerowsecurity,
            case
                when namespaces.oid = pg_my_temp_schema()
                    and relations.relpersistence = 't'
                    then 'p'
                else relations.relpersistence::text
            end,
            coalesce(access_methods.amname, ''),
            coalesce((
                select jsonb_agg(option order by option)
                from unnest(relations.reloptions) option
            ), '[]'::jsonb),
            relations.relispartition,
            relations.relreplident::text,
            case
                when namespaces.oid = pg_my_temp_schema() then ''
                else coalesce(tablespaces.spcname, '')
            end,
            coalesce(obj_description(relations.oid, 'pg_class'), '')
        )::text
        from pg_class relations
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        left join pg_am access_methods on access_methods.oid = relations.relam
        left join pg_tablespace tablespaces on tablespaces.oid = relations.reltablespace
        where namespaces.nspname = $1
          and relations.relkind not in ('i', 'I')
        order by relations.relname
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    let columns = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            relations.relname,
            attributes.attnum,
            attributes.attname,
            format_type(attributes.atttypid, attributes.atttypmod),
            attributes.attnotnull,
            coalesce(pg_get_expr(defaults.adbin, defaults.adrelid, false), ''),
            attributes.attidentity::text,
            attributes.attgenerated::text,
            attributes.attndims,
            attributes.attislocal,
            attributes.attinhcount,
            attributes.atthasmissing,
            coalesce(attributes.attmissingval::text, ''),
            attributes.attstorage::text,
            attributes.attcompression::text,
            attributes.attstattarget,
            coalesce((
                select jsonb_agg(option order by option)
                from unnest(attributes.attoptions) option
            ), '[]'::jsonb),
            coalesce((
                select jsonb_agg(option order by option)
                from unnest(attributes.attfdwoptions) option
            ), '[]'::jsonb),
            coalesce(collations.collname, ''),
            coalesce(attributes.attacl::text, ''),
            coalesce(col_description(relations.oid, attributes.attnum), '')
        )::text
        from pg_attribute attributes
        join pg_class relations on relations.oid = attributes.attrelid
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        left join pg_attrdef defaults
          on defaults.adrelid = relations.oid and defaults.adnum = attributes.attnum
        left join pg_collation collations on collations.oid = attributes.attcollation
        where namespaces.nspname = $1
          and relations.relkind in ('r', 'p', 'v', 'm', 'f')
          and attributes.attnum > 0
          and not attributes.attisdropped
        order by relations.relname, attributes.attnum
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    let constraints = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            relations.relname,
            constraints.conname,
            constraints.contype::text,
            constraints.condeferrable,
            constraints.condeferred,
            constraints.convalidated,
            constraints.connoinherit,
            pg_get_constraintdef(constraints.oid, false),
            coalesce(obj_description(constraints.oid, 'pg_constraint'), '')
        )::text
        from pg_constraint constraints
        join pg_class relations on relations.oid = constraints.conrelid
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        where namespaces.nspname = $1
        order by relations.relname, constraints.conname
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    let indexes = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            relations.relname,
            indexes.relname,
            catalog.indisunique,
            catalog.indisprimary,
            catalog.indisexclusion,
            catalog.indimmediate,
            catalog.indisvalid,
            catalog.indisready,
            catalog.indislive,
            catalog.indisreplident,
            catalog.indcheckxmin,
            case
                when namespaces.oid = pg_my_temp_schema()
                    and indexes.relpersistence = 't'
                    then 'p'
                else indexes.relpersistence::text
            end,
            pg_get_userbyid(indexes.relowner),
            access_methods.amname,
            coalesce((
                select jsonb_agg(option order by option)
                from unnest(indexes.reloptions) option
            ), '[]'::jsonb),
            case
                when namespaces.oid = pg_my_temp_schema() then ''
                else coalesce(tablespaces.spcname, '')
            end,
            coalesce(indexes.relacl::text, ''),
            coalesce(obj_description(indexes.oid, 'pg_class'), ''),
            pg_get_indexdef(indexes.oid, 0, false)
        )::text
        from pg_index catalog
        join pg_class indexes on indexes.oid = catalog.indexrelid
        join pg_class relations on relations.oid = catalog.indrelid
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        join pg_am access_methods on access_methods.oid = indexes.relam
        left join pg_tablespace tablespaces on tablespaces.oid = indexes.reltablespace
        where namespaces.nspname = $1
        order by relations.relname, indexes.relname
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    let triggers = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            relations.relname,
            triggers.tgname,
            triggers.tgenabled::text,
            pg_get_triggerdef(triggers.oid, false),
            coalesce(obj_description(triggers.oid, 'pg_trigger'), '')
        )::text
        from pg_trigger triggers
        join pg_class relations on relations.oid = triggers.tgrelid
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        where namespaces.nspname = $1
          and not triggers.tgisinternal
        order by relations.relname, triggers.tgname
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    let types = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            types.typname,
            pg_get_userbyid(types.typowner),
            types.typtype::text,
            types.typcategory::text,
            types.typispreferred,
            types.typnotnull,
            coalesce(types.typdefault, ''),
            coalesce(relations.relname, ''),
            coalesce(elements.typname, ''),
            coalesce(base_types.typname, ''),
            coalesce(array_types.typname, ''),
            coalesce(types.typacl::text, ''),
            coalesce(obj_description(types.oid, 'pg_type'), '')
        )::text
        from pg_type types
        join pg_namespace namespaces on namespaces.oid = types.typnamespace
        left join pg_class relations on relations.oid = types.typrelid
        left join pg_type elements on elements.oid = types.typelem
        left join pg_type base_types on base_types.oid = types.typbasetype
        left join pg_type array_types on array_types.oid = types.typarray
        where namespaces.nspname = $1
        order by types.typname
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    let routines = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            routines.proname,
            pg_get_function_identity_arguments(routines.oid),
            pg_get_userbyid(routines.proowner),
            routines.prokind::text,
            routines.prosecdef,
            routines.proleakproof,
            routines.provolatile::text,
            routines.proparallel::text,
            coalesce(routines.proacl::text, ''),
            coalesce(obj_description(routines.oid, 'pg_proc'), ''),
            pg_get_functiondef(routines.oid)
        )::text
        from pg_proc routines
        join pg_namespace namespaces on namespaces.oid = routines.pronamespace
        where namespaces.nspname = $1
        order by routines.proname, pg_get_function_identity_arguments(routines.oid)
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    let policies = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            relations.relname,
            policies.polname,
            policies.polcmd::text,
            policies.polpermissive,
            coalesce(policies.polroles::text, ''),
            coalesce(pg_get_expr(policies.polqual, policies.polrelid, false), ''),
            coalesce(pg_get_expr(policies.polwithcheck, policies.polrelid, false), '')
        )::text
        from pg_policy policies
        join pg_class relations on relations.oid = policies.polrelid
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        where namespaces.nspname = $1
        order by relations.relname, policies.polname
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    let inheritance = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            child_namespaces.nspname,
            children.relname,
            parent_namespaces.nspname,
            parents.relname,
            inheritance.inhseqno,
            inheritance.inhdetachpending
        )::text
        from pg_inherits inheritance
        join pg_class children on children.oid = inheritance.inhrelid
        join pg_namespace child_namespaces on child_namespaces.oid = children.relnamespace
        join pg_class parents on parents.oid = inheritance.inhparent
        join pg_namespace parent_namespaces on parent_namespaces.oid = parents.relnamespace
        where child_namespaces.nspname = $1 or parent_namespaces.nspname = $1
        order by child_namespaces.nspname, children.relname,
                 parent_namespaces.nspname, parents.relname, inheritance.inhseqno
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    let rules = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            relations.relname,
            rules.rulename,
            rules.ev_enabled::text,
            pg_get_ruledef(rules.oid, false)
        )::text
        from pg_rewrite rules
        join pg_class relations on relations.oid = rules.ev_class
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        where namespaces.nspname = $1
          and rules.rulename <> '_RETURN'
        order by relations.relname, rules.rulename
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    let security_labels = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            labels.classoid::regclass::text,
            labels.objoid,
            labels.objsubid,
            labels.provider,
            labels.label
        )::text
        from pg_seclabel labels
        where (
            labels.classoid = 'pg_namespace'::regclass
            and labels.objoid = (select oid from pg_namespace where nspname = $1)
        ) or (
            labels.classoid = 'pg_class'::regclass
            and labels.objoid in (
                select relations.oid
                from pg_class relations
                join pg_namespace namespaces on namespaces.oid = relations.relnamespace
                where namespaces.nspname = $1
            )
        ) or (
            labels.classoid = 'pg_proc'::regclass
            and labels.objoid in (
                select routines.oid
                from pg_proc routines
                join pg_namespace namespaces on namespaces.oid = routines.pronamespace
                where namespaces.nspname = $1
            )
        ) or (
            labels.classoid = 'pg_type'::regclass
            and labels.objoid in (
                select types.oid
                from pg_type types
                join pg_namespace namespaces on namespaces.oid = types.typnamespace
                where namespaces.nspname = $1
            )
        ) or (
            labels.classoid = 'pg_constraint'::regclass
            and labels.objoid in (
                select constraints.oid
                from pg_constraint constraints
                where constraints.connamespace = (
                    select oid from pg_namespace where nspname = $1
                )
            )
        )
        order by labels.classoid, labels.objoid, labels.objsubid, labels.provider
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    let publication_memberships = sqlx::query_scalar::<_, String>(
        r#"
        select jsonb_build_array(
            publications.pubname,
            relations.relname,
            coalesce(pg_get_expr(members.prqual, members.prrelid, false), ''),
            coalesce(members.prattrs::text, '')
        )::text
        from pg_publication_rel members
        join pg_publication publications on publications.oid = members.prpubid
        join pg_class relations on relations.oid = members.prrelid
        join pg_namespace namespaces on namespaces.oid = relations.relnamespace
        where namespaces.nspname = $1
        order by publications.pubname, relations.relname
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *connection)
    .await?;

    Ok(LegacySchemaFingerprint {
        schema: schema_fingerprint,
        relations,
        columns,
        constraints,
        indexes,
        triggers,
        types,
        routines,
        policies,
        inheritance,
        rules,
        security_labels,
        publication_memberships,
    })
}

fn migration_checksum(migration: &lenso_postgres_kit::Migration) -> String {
    let mut digest = Sha256::new();
    digest.update(migration.version().to_be_bytes());
    digest.update([0]);
    digest.update(migration.name().as_bytes());
    digest.update([0]);
    digest.update(migration.sql().as_bytes());
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_normalization_changes_only_identifier_qualifiers_in_sql_fields() {
        let mut rows = vec![serde_json::json!([
            "deliveries",
            "notification_delivery_status",
            "c",
            false,
            false,
            true,
            true,
            "CHECK (status = 'notification.delivery_unknown' AND notification.revision > 0 AND \"notification\".attempt_count >= 0 AND \"notification.keep\" = \"notification.keep\" AND note = $$notification.keep$$)",
            "notification."
        ])
        .to_string()];

        normalize_sql_fields(&mut rows, &[7], "notification");
        let normalized: serde_json::Value =
            serde_json::from_str(&rows[0]).expect("normalized catalog row");
        let definition = normalized[7].as_str().expect("constraint definition");
        assert!(definition.contains("'notification.delivery_unknown'"));
        assert!(definition.contains("$$notification.keep$$"));
        assert_eq!(definition.matches("\"notification.keep\"").count(), 2);
        assert!(!definition.contains("notification.revision"));
        assert!(!definition.contains("\"notification\".attempt_count"));
        assert!(definition.contains("revision > 0"));
        assert!(definition.contains("attempt_count >= 0"));
        assert_eq!(normalized[8], "notification.");
    }
}
