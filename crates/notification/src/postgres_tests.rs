use chrono::{Duration, Utc};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;

use crate::contracts::{
    DispatchOutcome, EMAIL_DISPATCH_OBSERVED_EVENT, EMAIL_RECEIPT_OBSERVED_EVENT,
    EmailDispatchObserved, EmailReceiptObserved, ReceiptKind, RemoteReceiptSummary,
    SanitizedFailure,
};
use crate::domain::{DeliveryStatus, MAX_SAFE_WIRE_INTEGER};
use crate::error::ErrorCode;
use crate::events::{NotificationEventApplier, ObservationEnvelope};
use crate::operator::{NotificationOperator, NotificationOperatorError};
use crate::plugin::format_time;
use crate::public::{
    AccessRequestNotificationEvent, AccessRequestNotificationTemplateV1, AccessRequestRoleV1,
    AccessRequestScopeV1, CreateAccessRequestNotificationIntent, CreateTransactionalEmailIntent,
    EmailRecipient, IntentSource, OrganizationInvitationTemplateV1, RenderedTemplate,
    create_access_request_notification_in_tx, create_transactional_email_intent_in_tx,
    find_transactional_email_intent_replay,
};
use crate::repository::PostgresNotificationRepository;
use crate::runtime::claim_one_due;
use crate::snapshot::TestSnapshotProtector;

#[tokio::test]
async fn plugin_owned_delivery_ledger_is_atomic_append_only_and_fail_closed() {
    let database_url = std::env::var("LENSO_TEST_DATABASE_URL");
    let Ok(database_url) = database_url else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI requires LENSO_TEST_DATABASE_URL so Postgres acceptance cannot be skipped"
        );
        eprintln!("skipping Postgres acceptance: LENSO_TEST_DATABASE_URL is not configured");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("connect test Postgres");
    let database_name: String = sqlx::query_scalar("select current_database()")
        .fetch_one(&pool)
        .await
        .expect("read test database name");
    assert!(
        database_name == "notification_test" || database_name.starts_with("notification_test_"),
        "refusing destructive test setup against non-test database {database_name}"
    );

    let expanded_year: chrono::DateTime<Utc> =
        sqlx::query_scalar("select timestamptz '10000-01-01 00:00:00+00'")
            .fetch_one(&pool)
            .await
            .expect("read PostgreSQL expanded-year timestamp");
    assert!(
        format_time(expanded_year).is_err(),
        "PostgreSQL expanded years must fail before Capability projection"
    );

    assert_legacy_ledger_tamper_rejected(
        &pool,
        &database_url,
        "delete from platform.schema_migrations where name = 'notification/0001_create_notification_schema'",
    )
    .await;
    assert_legacy_ledger_tamper_rejected(
        &pool,
        &database_url,
        "update platform.schema_migrations set name = 'notification/0001_wrong' where name = 'notification/0001_create_notification_schema'",
    )
    .await;
    assert_legacy_ledger_tamper_rejected(
        &pool,
        &database_url,
        "alter table platform.schema_migrations alter column applied_at drop default",
    )
    .await;
    assert_legacy_ledger_tamper_rejected(
        &pool,
        &database_url,
        "grant select on platform.schema_migrations to public",
    )
    .await;
    assert_legacy_ledger_tamper_rejected(
        &pool,
        &database_url,
        "revoke usage on type platform.schema_migrations from public",
    )
    .await;
    assert_legacy_ledger_tamper_rejected(
        &pool,
        &database_url,
        "comment on table platform.schema_migrations is 'unexpected provenance override'",
    )
    .await;
    assert_legacy_ledger_tamper_rejected(
        &pool,
        &database_url,
        r#"
        create function platform.unexpected_ledger_trigger() returns trigger
        language plpgsql as $$ begin return new; end $$;
        create trigger unexpected_ledger_trigger
            before insert on platform.schema_migrations
            for each row execute function platform.unexpected_ledger_trigger();
        "#,
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        "alter default privileges in schema platform grant select on tables to public",
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        r#"
        alter table notification.deliveries
            drop constraint notification_delivery_status;
        alter table notification.deliveries
            add constraint notification_delivery_status check (
                status in ('queued', 'attempting', 'accepted', 'retry_scheduled',
                           'delivered', 'failed', 'notification.delivery_unknown')
            );
        "#,
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        "alter table notification.deliveries alter column max_attempts set default 9",
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        r#"
        alter table notification.deliveries
            drop constraint notification_delivery_channel;
        alter table notification.deliveries
            add constraint notification_delivery_channel check (channel in ('email', 'sms'));
        "#,
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        r#"
        drop index notification.notification_deliveries_due_idx;
        create index notification_deliveries_due_idx
            on notification.deliveries (next_attempt_at, id)
            where status = 'queued';
        "#,
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        r#"
        alter table notification.intents
            add constraint notification_extra_intent_check check (length(source_module) > 0)
        "#,
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        "create index notification_extra_intents_idx on notification.intents (id, source_module)",
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        "comment on column notification.intents.recipient_ciphertext is 'unsafe plaintext access'",
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        "grant select (recipient_ciphertext) on notification.intents to public",
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        "grant select on notification.intents to public",
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        "grant usage on schema notification to public",
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        r#"
        create function notification.unexpected_routine() returns integer
        language sql immutable as $$ select 1 $$
        "#,
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        "alter table notification.intents set (fillfactor = 70)",
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        "alter default privileges in schema notification grant select on tables to public",
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        "create text search dictionary notification.unexpected_dictionary (template = simple)",
    )
    .await;
    assert_legacy_tamper_rejected(
        &pool,
        &database_url,
        "create statistics notification.unexpected_statistics on status, revision from notification.deliveries",
    )
    .await;
    assert_global_default_acl_tamper_rejected(&pool, &database_url).await;
    assert_legacy_publication_tamper_rejected(
        &pool,
        &database_url,
        "create publication notification_schema_publication for tables in schema notification",
        "notification_schema_publication",
    )
    .await;
    assert_legacy_publication_tamper_rejected(
        &pool,
        &database_url,
        "create publication notification_all_publication for all tables",
        "notification_all_publication",
    )
    .await;

    reset_legacy_schema(&pool).await;
    sqlx::query(
        r#"
        insert into notification.template_releases (
            id, template_id, version, locale, renderer_identity, template_digest, created_at
        ) values ('legacy-proof', 'legacy-proof', 'v1', 'en', 'legacy', $1, now())
        "#,
    )
    .bind(format!("sha256:{}", "c".repeat(64)))
    .execute(&pool)
    .await
    .expect("seed legacy row before adoption");

    let mut maintenance_guard = pool
        .begin()
        .await
        .expect("begin shared maintenance lock proof");
    sqlx::query(
        "select pg_advisory_xact_lock(hashtextextended(current_database() || ':lenso-maintenance', 0))",
    )
    .execute(maintenance_guard.as_mut())
    .await
    .expect("hold shared maintenance advisory key");
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(250),
            NotificationOperator::adopt_legacy(&database_url),
        )
        .await
        .is_err(),
        "legacy adoption must wait for the shared maintenance protocol key",
    );
    maintenance_guard
        .rollback()
        .await
        .expect("release shared maintenance advisory key");

    let adopted = NotificationOperator::adopt_legacy(&database_url)
        .await
        .expect("adopt exact legacy schema without rewriting data");
    assert_eq!(adopted.version, 1);
    let legacy_rows: i64 = sqlx::query_scalar(
        "select count(*) from notification.template_releases where id = 'legacy-proof'",
    )
    .fetch_one(&pool)
    .await
    .expect("verify adopted legacy data");
    assert_eq!(legacy_rows, 1);
    let unrelated_legacy_rows: i64 = sqlx::query_scalar(
        "select count(*) from platform.schema_migrations where name = 'other/0001_fixture'",
    )
    .fetch_one(&pool)
    .await
    .expect("verify unrelated legacy Host ledger rows are preserved");
    assert_eq!(unrelated_legacy_rows, 1);
    NotificationOperator::upgrade(&database_url)
        .await
        .expect("upgrade adopted legacy schema to current Plugin migrations");
    let prepared = NotificationOperator::connect(&database_url)
        .await
        .expect("managed schema must pass runtime preparation");
    assert_eq!(prepared.schema(), "notification");
    sqlx::raw_sql(
        r#"
        create table notification.post_adoption_extra (id bigint primary key);
        create function notification.post_adoption_extra_function() returns integer
        language sql immutable as $$ select 1 $$;
        "#,
    )
    .execute(&pool)
    .await
    .expect("simulate schema-local DDL after adoption");
    let managed_error = NotificationOperator::connect(&database_url)
        .await
        .expect_err("managed preparation must reject later catalog additions");
    assert!(matches!(
        managed_error,
        NotificationOperatorError::ManagedSchemaMismatch
    ));
    sqlx::raw_sql(
        r#"
        drop function notification.post_adoption_extra_function();
        drop table notification.post_adoption_extra;
        "#,
    )
    .execute(&pool)
    .await
    .expect("remove post-adoption DDL fixture");
    NotificationOperator::connect(&database_url)
        .await
        .expect("managed preparation recovers after exact catalog is restored");
    assert_managed_publication_tamper_rejected(
        &pool,
        &database_url,
        "create publication notification_schema_publication for tables in schema notification",
        "notification_schema_publication",
    )
    .await;
    assert_managed_publication_tamper_rejected(
        &pool,
        &database_url,
        "create publication notification_all_publication for all tables",
        "notification_all_publication",
    )
    .await;
    assert_managed_schema_tamper_rejected(
        &pool,
        &database_url,
        "create text search dictionary notification.unexpected_dictionary (template = simple)",
        "drop text search dictionary notification.unexpected_dictionary",
    )
    .await;
    assert_managed_schema_tamper_rejected(
        &pool,
        &database_url,
        "create statistics notification.unexpected_statistics on status, revision from notification.deliveries",
        "drop statistics notification.unexpected_statistics",
    )
    .await;
    truncate_notification_ledger(&pool).await;

    let now = Utc::now();
    let mut blue_request = invitation_request(now, "shared-blue");
    blue_request.source.module_id = "organization-blue".to_owned();
    blue_request.source.entity_id = "org_invite_shared".to_owned();
    blue_request.template.invitation_id = "org_invite_shared".to_owned();
    let mut blue_tx = pool.begin().await.expect("begin blue caller intent");
    let blue = create_transactional_email_intent_in_tx(
        &mut blue_tx,
        &blue_request,
        &invitation_render(&blue_request),
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect("create blue caller intent");
    blue_tx.commit().await.expect("commit blue caller intent");

    let mut red_request = invitation_request(now, "shared-red");
    red_request.source.module_id = "organization-red".to_owned();
    red_request.source.entity_id = "org_invite_shared".to_owned();
    red_request.template.invitation_id = "org_invite_shared".to_owned();
    let mut red_tx = pool.begin().await.expect("begin red caller intent");
    let red = create_transactional_email_intent_in_tx(
        &mut red_tx,
        &red_request,
        &invitation_render(&red_request),
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect("create red caller intent");
    red_tx.commit().await.expect("commit red caller intent");

    let lifecycle_at = now + Duration::seconds(1);
    NotificationEventApplier::new(pool.clone())
        .apply(&ObservationEnvelope {
            id: "obs_invitation_shared_blue".to_owned(),
            event_name: crate::contracts::ORGANIZATION_INVITATION_REVOKED_EVENT.to_owned(),
            event_version: 1,
            source_module: "organization-blue".to_owned(),
            aggregate_id: "org_invite_shared".to_owned(),
            occurred_at: lifecycle_at,
            payload: serde_json::to_value(crate::contracts::OrganizationInvitationLifecycle {
                invitation_id: "org_invite_shared".to_owned(),
                organization_id: "org_test".to_owned(),
                observed_at: lifecycle_at,
            })
            .expect("encode caller-scoped lifecycle"),
        })
        .await
        .expect("apply caller-scoped lifecycle");
    let scoped_repository = PostgresNotificationRepository::from_pool(pool.clone());
    let blue_detail = scoped_repository
        .get_delivery(&blue.delivery_id)
        .await
        .expect("load blue caller delivery")
        .expect("blue caller delivery exists");
    let red_detail = scoped_repository
        .get_delivery(&red.delivery_id)
        .await
        .expect("load red caller delivery")
        .expect("red caller delivery exists");
    assert_eq!(blue_detail.delivery.status, "failed");
    assert_eq!(red_detail.delivery.status, "queued");
    let lifecycle_source: String = sqlx::query_scalar(
        "select source_module from notification.source_lifecycle_events where event_id = 'obs_invitation_shared_blue'",
    )
    .fetch_one(&pool)
    .await
    .expect("read caller-derived lifecycle source");
    assert_eq!(lifecycle_source, "organization-blue");

    NotificationEventApplier::new(pool.clone())
        .apply(&ObservationEnvelope {
            id: "obs_invitation_shared_red_expired".to_owned(),
            event_name: crate::contracts::ORGANIZATION_INVITATION_EXPIRED_EVENT.to_owned(),
            event_version: 1,
            source_module: "organization-red".to_owned(),
            aggregate_id: "org_invite_shared".to_owned(),
            occurred_at: lifecycle_at,
            payload: serde_json::to_value(crate::contracts::OrganizationInvitationLifecycle {
                invitation_id: "org_invite_shared".to_owned(),
                organization_id: "org_test".to_owned(),
                observed_at: lifecycle_at,
            })
            .expect("encode expired caller-scoped lifecycle"),
        })
        .await
        .expect("apply expired caller-scoped lifecycle");
    let red_after_expiry = scoped_repository
        .get_delivery(&red.delivery_id)
        .await
        .expect("load expired red caller delivery")
        .expect("expired red caller delivery exists");
    assert_eq!(red_after_expiry.delivery.status, "failed");
    let expired_lifecycle: String = sqlx::query_scalar(
        "select lifecycle from notification.source_lifecycle_events where event_id = 'obs_invitation_shared_red_expired'",
    )
    .fetch_one(&pool)
    .await
    .expect("read expired lifecycle");
    assert_eq!(expired_lifecycle, "expired");

    truncate_notification_ledger(&pool).await;
    let access_request =
        access_request_notification(now, AccessRequestNotificationEvent::Submitted);
    let mut access_tx = pool.begin().await.expect("begin access-request intent");
    let access_receipt = create_access_request_notification_in_tx(
        &mut access_tx,
        &access_request,
        &access_request_render(&access_request),
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect("create access-request intent");
    access_tx
        .commit()
        .await
        .expect("commit access-request intent");
    assert!(!access_receipt.idempotent_replay);

    let restarted_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("restart Notification connection for access-request replay");
    let mut access_replay_tx = restarted_pool
        .begin()
        .await
        .expect("begin restarted access-request replay");
    let access_replay = create_access_request_notification_in_tx(
        &mut access_replay_tx,
        &access_request,
        &access_request_render(&access_request),
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect("replay access-request intent after restart");
    access_replay_tx
        .commit()
        .await
        .expect("commit restarted access-request replay");
    assert!(access_replay.idempotent_replay);
    assert_eq!(access_replay.intent_id, access_receipt.intent_id);

    let mut changed_access_request = access_request.clone();
    changed_access_request.template.role.display_name = Some("Owner".to_owned());
    let mut access_conflict_tx = restarted_pool
        .begin()
        .await
        .expect("begin access-request conflict");
    let access_conflict = create_access_request_notification_in_tx(
        &mut access_conflict_tx,
        &changed_access_request,
        &access_request_render(&changed_access_request),
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect_err("same request/event with changed display input must conflict");
    assert_eq!(access_conflict.code, ErrorCode::Conflict);
    access_conflict_tx
        .rollback()
        .await
        .expect("rollback access-request conflict");

    let approved = access_request_notification(now, AccessRequestNotificationEvent::Approved);
    let mut approved_tx = restarted_pool
        .begin()
        .await
        .expect("begin approved access-request intent");
    let approved_receipt = create_access_request_notification_in_tx(
        &mut approved_tx,
        &approved,
        &access_request_render(&approved),
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect("create distinct approved access-request intent");
    approved_tx
        .commit()
        .await
        .expect("commit approved access-request intent");
    assert_ne!(approved_receipt.intent_id, access_receipt.intent_id);
    let access_purposes: i64 = sqlx::query_scalar(
        "select count(*) from notification.intents where purpose='transactional.access_request' and source_entity_id='ar_notification_1'",
    )
    .fetch_one(&restarted_pool)
    .await
    .expect("count durable access-request intents");
    assert_eq!(access_purposes, 2);
    let templates: Vec<String> = sqlx::query_scalar(
        "select template_id from notification.template_releases where template_id like 'access-request-%' order by template_id",
    )
    .fetch_all(&restarted_pool)
    .await
    .expect("read access-request template releases");
    assert_eq!(
        templates,
        vec![
            "access-request-approved".to_owned(),
            "access-request-submitted".to_owned(),
        ]
    );
    restarted_pool.close().await;

    truncate_notification_ledger(&pool).await;
    let request = invitation_request(now, "primary");
    let mut first_tx = pool.begin().await.expect("begin intent transaction");
    let first = create_transactional_email_intent_in_tx(
        &mut first_tx,
        &request,
        &invitation_render(&request),
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect("create intent");
    first_tx.commit().await.expect("commit intent");
    assert_eq!(first.status, DeliveryStatus::Queued);
    assert!(!first.idempotent_replay);
    let fast_replay = find_transactional_email_intent_replay(&pool, &request, now)
        .await
        .expect("read committed replay without rendering")
        .expect("committed replay exists");
    assert_eq!(fast_replay.intent_id, first.intent_id);
    assert!(fast_replay.idempotent_replay);

    let mut replay_tx = pool.begin().await.expect("begin replay transaction");
    let replay = create_transactional_email_intent_in_tx(
        &mut replay_tx,
        &request,
        &invitation_render(&request),
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect("replay intent");
    replay_tx.commit().await.expect("commit replay");
    assert_eq!(replay.intent_id, first.intent_id);
    assert_eq!(replay.delivery_id, first.delivery_id);
    assert!(replay.idempotent_replay);

    let mut changed = request.clone();
    changed.recipient.address = "different@example.com".to_owned();
    let fast_conflict = find_transactional_email_intent_replay(&pool, &changed, now)
        .await
        .expect_err("changed input must conflict before rendering");
    assert_eq!(fast_conflict.code, ErrorCode::Conflict);
    let mut conflict_tx = pool.begin().await.expect("begin conflict transaction");
    let conflict = create_transactional_email_intent_in_tx(
        &mut conflict_tx,
        &changed,
        &invitation_render(&changed),
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect_err("same key with changed input must conflict");
    assert_eq!(conflict.code, ErrorCode::Conflict);
    conflict_tx.rollback().await.expect("rollback conflict");

    let leaked: i64 = sqlx::query_scalar(
        r#"
        select count(*)
        from notification.intents intents
        join notification.render_snapshots snapshots on snapshots.id = intents.snapshot_id
        where intents.recipient_ciphertext like '%member@example.com%'
           or snapshots.text_ciphertext like '%secret-token%'
           or snapshots.html_ciphertext like '%secret-token%'
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("scan protected columns");
    assert_eq!(leaked, 0);

    let first_work = claim_one_due(&pool, &TestSnapshotProtector, now)
        .await
        .expect("claim first attempt")
        .expect("queued delivery is due");
    assert_eq!(first_work.claim.delivery_id, first.delivery_id);
    assert_eq!(first_work.request.recipient.address, "member@example.com");
    assert!(
        first_work
            .request
            .message
            .text
            .contains("secret-token-primary")
    );
    let applier = NotificationEventApplier::new(pool.clone());
    let first_failed_at = now + Duration::seconds(1);
    let temporary_failure = EmailDispatchObserved {
        delivery_id: first.delivery_id.clone(),
        attempt_id: first_work.claim.attempt_id.clone(),
        function_run_id: first_work.claim.run_id.clone(),
        outcome: DispatchOutcome::TemporaryFailure,
        provider: "fixture.email-dispatch".to_owned(),
        observed_at: first_failed_at,
        remote_receipt: None,
        failure: Some(SanitizedFailure {
            code: "provider_rate_limited".to_owned(),
            classification: "temporary_failure".to_owned(),
            retry_after_ms: Some(120_000),
        }),
    };
    let failed = event(
        "obs_dispatch_failed_primary",
        EMAIL_DISPATCH_OBSERVED_EVENT,
        &temporary_failure,
        first_failed_at,
    );
    applier.apply(&failed).await.expect("schedule retry");
    applier
        .apply(&failed)
        .await
        .expect("replay observation idempotently");
    assert!(
        claim_one_due(
            &pool,
            &TestSnapshotProtector,
            first_failed_at + Duration::seconds(119),
        )
        .await
        .expect("check retry-after")
        .is_none(),
        "provider retry-after must prevent an early automatic retry"
    );

    let repository = PostgresNotificationRepository::from_pool(pool.clone());
    let scheduled = repository
        .get_delivery(&first.delivery_id)
        .await
        .expect("load retry candidate")
        .expect("delivery exists");
    assert_eq!(scheduled.delivery.status, "retry_scheduled");
    let manual_retry_at = first_failed_at + Duration::seconds(2);
    let retry = repository
        .request_manual_retry(
            &first.delivery_id,
            scheduled.delivery.revision,
            "manual-retry-primary",
            "operator-fixture",
            manual_retry_at,
        )
        .await
        .expect("schedule explicit manual retry");
    assert!(!retry.idempotent_replay);
    let retry_replay = repository
        .request_manual_retry(
            &first.delivery_id,
            scheduled.delivery.revision,
            "manual-retry-primary",
            "operator-fixture",
            manual_retry_at,
        )
        .await
        .expect("replay manual retry request");
    assert!(retry_replay.idempotent_replay);

    let second_work = claim_one_due(&pool, &TestSnapshotProtector, manual_retry_at)
        .await
        .expect("claim manually scheduled attempt")
        .expect("manual retry is due");
    assert_ne!(second_work.claim.attempt_id, first_work.claim.attempt_id);
    let accepted_at = manual_retry_at + Duration::seconds(1);
    applier
        .apply(&event(
            "obs_dispatch_accepted_primary",
            EMAIL_DISPATCH_OBSERVED_EVENT,
            &EmailDispatchObserved {
                delivery_id: first.delivery_id.clone(),
                attempt_id: second_work.claim.attempt_id.clone(),
                function_run_id: second_work.claim.run_id.clone(),
                outcome: DispatchOutcome::Accepted,
                provider: "fixture.email-dispatch".to_owned(),
                observed_at: accepted_at,
                remote_receipt: Some(RemoteReceiptSummary {
                    source: "fixture.email-dispatch".to_owned(),
                    remote_id: "remote-primary".to_owned(),
                    digest: format!("sha256:{}", "b".repeat(64)),
                }),
                failure: None,
            },
            accepted_at,
        ))
        .await
        .expect("record provider acceptance");
    let delivered_at = accepted_at + Duration::seconds(1);
    applier
        .apply(&event(
            "obs_receipt_delivered_primary",
            EMAIL_RECEIPT_OBSERVED_EVENT,
            &EmailReceiptObserved {
                delivery_id: first.delivery_id.clone(),
                attempt_id: second_work.claim.attempt_id.clone(),
                function_run_id: second_work.claim.run_id.clone(),
                kind: ReceiptKind::Delivered,
                source: "fixture.email-dispatch".to_owned(),
                observed_at: delivered_at,
                remote_id: "remote-primary".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
            },
            delivered_at,
        ))
        .await
        .expect("record authoritative delivery receipt");
    let delivered = repository
        .get_delivery(&first.delivery_id)
        .await
        .expect("load delivered state")
        .expect("delivery exists");
    assert_eq!(delivered.delivery.status, "delivered");
    assert_eq!(delivered.attempts.len(), 2);
    assert_eq!(delivered.receipts.len(), 2);
    assert_eq!(delivered.retry_requests.len(), 2);
    let redacted = serde_json::to_string(&delivered).expect("serialize redacted projection");
    assert!(!redacted.contains("member@example.com"));
    assert!(!redacted.contains("secret-token"));

    let unknown_request = invitation_request(delivered_at + Duration::seconds(1), "unknown");
    let mut unknown_tx = pool
        .begin()
        .await
        .expect("begin unknown intent transaction");
    let unknown = create_transactional_email_intent_in_tx(
        &mut unknown_tx,
        &unknown_request,
        &invitation_render(&unknown_request),
        delivered_at + Duration::seconds(1),
        &TestSnapshotProtector,
    )
    .await
    .expect("create ambiguous-effect intent");
    unknown_tx.commit().await.expect("commit unknown intent");
    let unknown_work = claim_one_due(
        &pool,
        &TestSnapshotProtector,
        delivered_at + Duration::seconds(1),
    )
    .await
    .expect("claim ambiguous-effect attempt")
    .expect("second delivery is due");
    let unknown_at = delivered_at + Duration::seconds(2);
    applier
        .apply(&event(
            "obs_dispatch_unknown",
            EMAIL_DISPATCH_OBSERVED_EVENT,
            &EmailDispatchObserved {
                delivery_id: unknown.delivery_id.clone(),
                attempt_id: unknown_work.claim.attempt_id,
                function_run_id: unknown_work.claim.run_id,
                outcome: DispatchOutcome::DeliveryUnknown,
                provider: "fixture.email-dispatch".to_owned(),
                observed_at: unknown_at,
                remote_receipt: None,
                failure: Some(SanitizedFailure {
                    code: "provider_result_ambiguous".to_owned(),
                    classification: "delivery_unknown".to_owned(),
                    retry_after_ms: None,
                }),
            },
            unknown_at,
        ))
        .await
        .expect("record ambiguous external effect");
    let terminal = repository
        .get_delivery(&unknown.delivery_id)
        .await
        .expect("load terminal delivery")
        .expect("delivery exists");
    assert_eq!(terminal.delivery.status, "delivery_unknown");
    assert_eq!(terminal.attempts.len(), 1);
    assert!(terminal.receipts.is_empty());
    assert!(
        claim_one_due(
            &pool,
            &TestSnapshotProtector,
            unknown_at + Duration::hours(1),
        )
        .await
        .expect("check terminal eligibility")
        .is_none(),
        "delivery_unknown must never be retried automatically"
    );

    sqlx::query(
        r#"
        insert into notification.receipts (
            id, delivery_id, attempt_id, kind, source, remote_id, digest,
            observed_at, recorded_at
        )
        select 'overflow_receipt_' || sequence, $1, $2, 'accepted',
               'overflow-fixture', 'overflow-remote-' || sequence, $3, $4, $4
        from generate_series(1, 999) as sequence
        "#,
    )
    .bind(&first.delivery_id)
    .bind(&second_work.claim.attempt_id)
    .bind(format!("sha256:{}", "d".repeat(64)))
    .bind(unknown_at)
    .execute(&pool)
    .await
    .expect("seed evidence just beyond the bounded Admin projection");
    let overflow = repository
        .get_delivery(&first.delivery_id)
        .await
        .expect_err("detail projection must reject rather than truncate evidence");
    assert_eq!(overflow.code, ErrorCode::EvidenceOverflow);

    assert_revision_overflow_paths_fail_closed(&pool).await;
}

async fn assert_revision_overflow_paths_fail_closed(pool: &sqlx::PgPool) {
    truncate_notification_ledger(pool).await;
    let now = Utc::now();

    let claim_delivery = seed_intent(pool, now, "revision-claim").await;
    sqlx::query("update notification.deliveries set revision = $2 where id = $1")
        .bind(&claim_delivery)
        .bind(MAX_SAFE_WIRE_INTEGER)
        .execute(pool)
        .await
        .expect("seed exhausted claim revision");
    let claim_error = claim_one_due(pool, &TestSnapshotProtector, now)
        .await
        .expect_err("dispatch claim must reject an exhausted portable revision");
    assert_eq!(claim_error.code, ErrorCode::Conflict);
    let claim_state: (String, i64, i64) = sqlx::query_as(
        r#"
        select deliveries.status, deliveries.revision,
               (select count(*) from notification.attempts attempts where attempts.delivery_id = deliveries.id)
        from notification.deliveries deliveries where deliveries.id = $1
        "#,
    )
    .bind(&claim_delivery)
    .fetch_one(pool)
    .await
    .expect("read fail-closed claim state");
    assert_eq!(claim_state, ("queued".to_owned(), MAX_SAFE_WIRE_INTEGER, 0));

    truncate_notification_ledger(pool).await;

    let observed_delivery = seed_intent(pool, now, "revision-observation").await;
    let work = claim_one_due(pool, &TestSnapshotProtector, now)
        .await
        .expect("claim observation fixture")
        .expect("observation fixture is due");
    assert_eq!(work.claim.delivery_id, observed_delivery);
    sqlx::query("update notification.deliveries set revision = $2 where id = $1")
        .bind(&observed_delivery)
        .bind(MAX_SAFE_WIRE_INTEGER)
        .execute(pool)
        .await
        .expect("seed exhausted observation revision");
    let applier = NotificationEventApplier::new(pool.clone());
    let dispatch_id = "obs_revision_dispatch";
    let dispatch_error = applier
        .apply(&event(
            dispatch_id,
            EMAIL_DISPATCH_OBSERVED_EVENT,
            &EmailDispatchObserved {
                delivery_id: observed_delivery.clone(),
                attempt_id: work.claim.attempt_id.clone(),
                function_run_id: work.claim.run_id.clone(),
                outcome: DispatchOutcome::Accepted,
                provider: "fixture.email-dispatch".to_owned(),
                observed_at: now,
                remote_receipt: None,
                failure: None,
            },
            now,
        ))
        .await
        .expect_err("dispatch observation must reject an exhausted portable revision");
    assert_eq!(dispatch_error.code, ErrorCode::Conflict);

    let receipt_id = "obs_revision_receipt";
    let receipt_error = applier
        .apply(&event(
            receipt_id,
            EMAIL_RECEIPT_OBSERVED_EVENT,
            &EmailReceiptObserved {
                delivery_id: observed_delivery.clone(),
                attempt_id: work.claim.attempt_id.clone(),
                function_run_id: work.claim.run_id,
                kind: ReceiptKind::Delivered,
                source: "fixture.email-dispatch".to_owned(),
                observed_at: now,
                remote_id: "remote-revision".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
            },
            now,
        ))
        .await
        .expect_err("receipt observation must reject an exhausted portable revision");
    assert_eq!(receipt_error.code, ErrorCode::Conflict);
    let observation_state: (String, i64, String, i64, i64) = sqlx::query_as(
        r#"
        select deliveries.status, deliveries.revision, attempts.status,
               (select count(*) from notification.receipts receipts where receipts.delivery_id = deliveries.id),
               (select count(*) from notification.consumed_events consumed where consumed.event_id in ($3, $4))
        from notification.deliveries deliveries
        join notification.attempts attempts on attempts.delivery_id = deliveries.id
        where deliveries.id = $1 and attempts.id = $2
        "#,
    )
    .bind(&observed_delivery)
    .bind(&work.claim.attempt_id)
    .bind(dispatch_id)
    .bind(receipt_id)
    .fetch_one(pool)
    .await
    .expect("read fail-closed observation state");
    assert_eq!(
        observation_state,
        (
            "attempting".to_owned(),
            MAX_SAFE_WIRE_INTEGER,
            "dispatching".to_owned(),
            0,
            0,
        )
    );

    truncate_notification_ledger(pool).await;

    let lifecycle_delivery = seed_intent(pool, now, "revision-lifecycle").await;
    sqlx::query("update notification.deliveries set revision = $2 where id = $1")
        .bind(&lifecycle_delivery)
        .bind(MAX_SAFE_WIRE_INTEGER)
        .execute(pool)
        .await
        .expect("seed exhausted lifecycle revision");
    let lifecycle_id = "obs_revision_lifecycle";
    let lifecycle_error = applier
        .apply(&ObservationEnvelope {
            id: lifecycle_id.to_owned(),
            event_name: crate::contracts::ORGANIZATION_INVITATION_REVOKED_EVENT.to_owned(),
            event_version: 1,
            source_module: "organization".to_owned(),
            aggregate_id: "org_invite_revision-lifecycle".to_owned(),
            occurred_at: now,
            payload: serde_json::to_value(crate::contracts::OrganizationInvitationLifecycle {
                invitation_id: "org_invite_revision-lifecycle".to_owned(),
                organization_id: "org_test".to_owned(),
                observed_at: now,
            })
            .expect("encode exhausted lifecycle fixture"),
        })
        .await
        .expect_err("lifecycle observation must reject an exhausted portable revision");
    assert_eq!(lifecycle_error.code, ErrorCode::Conflict);
    let lifecycle_state: (String, i64, i64, i64) = sqlx::query_as(
        r#"
        select deliveries.status, deliveries.revision,
               (select count(*) from notification.source_lifecycle_events events where events.event_id = $2),
               (select count(*) from notification.consumed_events consumed where consumed.event_id = $2)
        from notification.deliveries deliveries where deliveries.id = $1
        "#,
    )
    .bind(&lifecycle_delivery)
    .bind(lifecycle_id)
    .fetch_one(pool)
    .await
    .expect("read fail-closed lifecycle state");
    assert_eq!(
        lifecycle_state,
        ("queued".to_owned(), MAX_SAFE_WIRE_INTEGER, 0, 0)
    );

    truncate_notification_ledger(pool).await;

    let retry_delivery = seed_intent(pool, now, "revision-manual").await;
    sqlx::query(
        "update notification.deliveries set status = 'retry_scheduled', revision = $2 where id = $1",
    )
    .bind(&retry_delivery)
    .bind(MAX_SAFE_WIRE_INTEGER)
    .execute(pool)
    .await
    .expect("seed exhausted manual-retry revision");
    let retry_error = PostgresNotificationRepository::from_pool(pool.clone())
        .request_manual_retry(
            &retry_delivery,
            MAX_SAFE_WIRE_INTEGER,
            "retry-revision-overflow",
            "console-blue",
            now,
        )
        .await
        .expect_err("manual retry must reject an exhausted portable revision");
    assert_eq!(retry_error.code, ErrorCode::Conflict);
    let retry_state: (i64, i64) = sqlx::query_as(
        r#"
        select deliveries.revision,
               (select count(*) from notification.retry_requests retries where retries.delivery_id = deliveries.id)
        from notification.deliveries deliveries where deliveries.id = $1
        "#,
    )
    .bind(&retry_delivery)
    .fetch_one(pool)
    .await
    .expect("read fail-closed manual-retry state");
    assert_eq!(retry_state, (MAX_SAFE_WIRE_INTEGER, 0));
}

async fn seed_intent(pool: &sqlx::PgPool, now: chrono::DateTime<Utc>, suffix: &str) -> String {
    let request = invitation_request(now, suffix);
    let mut transaction = pool.begin().await.expect("begin revision fixture intent");
    let receipt = create_transactional_email_intent_in_tx(
        &mut transaction,
        &request,
        &invitation_render(&request),
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect("create revision fixture intent");
    transaction
        .commit()
        .await
        .expect("commit revision fixture intent");
    receipt.delivery_id
}

async fn assert_legacy_tamper_rejected(
    pool: &sqlx::PgPool,
    database_url: &str,
    tamper_sql: &'static str,
) {
    reset_legacy_schema(pool).await;
    sqlx::raw_sql(tamper_sql)
        .execute(pool)
        .await
        .expect("tamper legacy schema fixture");
    let error = NotificationOperator::adopt_legacy(database_url)
        .await
        .expect_err("tampered or extended legacy schema must not be adopted");
    assert!(
        matches!(error, NotificationOperatorError::LegacySchemaMismatch),
        "unexpected legacy adoption error: {error}"
    );
    let ledger_exists: bool = sqlx::query_scalar(
        r#"
        select exists (
            select 1
            from pg_class relations
            join pg_namespace namespaces on namespaces.oid = relations.relnamespace
            where namespaces.nspname = 'notification'
              and relations.relname = '_lenso_schema_migrations'
        )
        "#,
    )
    .fetch_one(pool)
    .await
    .expect("check failed adoption did not create a ledger");
    assert!(!ledger_exists);
}

async fn assert_legacy_ledger_tamper_rejected(
    pool: &sqlx::PgPool,
    database_url: &str,
    tamper_sql: &'static str,
) {
    reset_legacy_schema(pool).await;
    sqlx::raw_sql(tamper_sql)
        .execute(pool)
        .await
        .expect("tamper legacy Host migration ledger fixture");
    let error = NotificationOperator::adopt_legacy(database_url)
        .await
        .expect_err("missing, wrong, or malformed legacy Host evidence must not be adopted");
    assert!(
        matches!(error, NotificationOperatorError::LegacyHostLedgerMismatch),
        "unexpected legacy adoption error: {error}"
    );
}

async fn assert_global_default_acl_tamper_rejected(pool: &sqlx::PgPool, database_url: &str) {
    reset_legacy_schema(pool).await;
    sqlx::query("alter default privileges revoke execute on functions from public")
        .execute(pool)
        .await
        .expect("tamper global function default privileges");
    let error = NotificationOperator::adopt_legacy(database_url)
        .await
        .expect_err("global default privileges must prevent legacy adoption");
    assert!(
        matches!(error, NotificationOperatorError::LegacySchemaMismatch),
        "unexpected legacy adoption error: {error}"
    );
    sqlx::query("alter default privileges grant execute on functions to public")
        .execute(pool)
        .await
        .expect("restore global function default privileges");
}

async fn assert_legacy_publication_tamper_rejected(
    pool: &sqlx::PgPool,
    database_url: &str,
    tamper_sql: &'static str,
    publication: &'static str,
) {
    reset_legacy_schema(pool).await;
    sqlx::query(tamper_sql)
        .execute(pool)
        .await
        .expect("publish legacy Notification schema fixture");
    let error = NotificationOperator::adopt_legacy(database_url)
        .await
        .expect_err("implicit publication scope must prevent legacy adoption");
    assert!(
        matches!(error, NotificationOperatorError::LegacySchemaMismatch),
        "unexpected legacy publication error: {error}"
    );
    sqlx::query(publication_drop_sql(publication))
        .execute(pool)
        .await
        .expect("remove legacy publication fixture");
}

async fn assert_managed_publication_tamper_rejected(
    pool: &sqlx::PgPool,
    database_url: &str,
    tamper_sql: &'static str,
    publication: &'static str,
) {
    sqlx::query(tamper_sql)
        .execute(pool)
        .await
        .expect("publish managed Notification schema fixture");
    let error = NotificationOperator::connect(database_url)
        .await
        .expect_err("implicit publication scope must prevent managed preparation");
    assert!(matches!(
        error,
        NotificationOperatorError::ManagedSchemaMismatch
    ));
    sqlx::query(publication_drop_sql(publication))
        .execute(pool)
        .await
        .expect("remove managed publication fixture");
    NotificationOperator::connect(database_url)
        .await
        .expect("managed preparation recovers after publication removal");
}

async fn assert_managed_schema_tamper_rejected(
    pool: &sqlx::PgPool,
    database_url: &str,
    tamper_sql: &'static str,
    restore_sql: &'static str,
) {
    sqlx::query(tamper_sql)
        .execute(pool)
        .await
        .expect("add unsupported managed schema object");
    let error = NotificationOperator::connect(database_url)
        .await
        .expect_err("unsupported schema object must prevent managed preparation");
    assert!(matches!(
        error,
        NotificationOperatorError::ManagedSchemaMismatch
    ));
    sqlx::query(restore_sql)
        .execute(pool)
        .await
        .expect("remove unsupported managed schema object");
    NotificationOperator::connect(database_url)
        .await
        .expect("managed preparation recovers after unsupported object removal");
}

fn publication_drop_sql(publication: &str) -> &'static str {
    match publication {
        "notification_schema_publication" => "drop publication notification_schema_publication",
        "notification_all_publication" => "drop publication notification_all_publication",
        _ => panic!("unknown fixed publication fixture"),
    }
}

async fn reset_legacy_schema(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        "drop publication if exists notification_schema_publication; drop publication if exists notification_all_publication;",
    )
    .execute(pool)
    .await
    .expect("remove stale publication fixtures");
    sqlx::query("drop schema if exists notification cascade")
        .execute(pool)
        .await
        .expect("reset dedicated Notification test schema");
    sqlx::raw_sql(include_str!(
        "../migrations/0001_create_notification_schema.sql"
    ))
    .execute(pool)
    .await
    .expect("apply immutable Notification migration");
    sqlx::raw_sql(
        r#"
        drop schema if exists platform cascade;
        create schema platform;
        create table platform.schema_migrations (
            name text primary key,
            applied_at timestamptz not null default now()
        );
        insert into platform.schema_migrations (name) values
            ('notification/0001_create_notification_schema'),
            ('other/0001_fixture');
        "#,
    )
    .execute(pool)
    .await
    .expect("create legacy Host migration ledger fixture");
}

async fn truncate_notification_ledger(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        r#"
        truncate table notification.source_lifecycle_events, notification.consumed_events,
            notification.retry_requests, notification.receipts, notification.attempts,
            notification.deliveries, notification.intents, notification.render_snapshots,
            notification.template_releases restart identity cascade
        "#,
    )
    .execute(pool)
    .await
    .expect("clean Notification schema");
}

fn event(
    id: &str,
    name: &str,
    payload: &impl Serialize,
    occurred_at: chrono::DateTime<Utc>,
) -> ObservationEnvelope {
    ObservationEnvelope {
        id: id.to_owned(),
        event_name: name.to_owned(),
        event_version: 1,
        source_module: "fixture.email-dispatch".to_owned(),
        aggregate_id: "notification-test".to_owned(),
        occurred_at,
        payload: serde_json::to_value(payload).expect("encode observation fixture"),
    }
}

fn invitation_request(now: chrono::DateTime<Utc>, suffix: &str) -> CreateTransactionalEmailIntent {
    CreateTransactionalEmailIntent {
        source: IntentSource {
            module_id: "organization".to_owned(),
            entity_type: "organization_invitation".to_owned(),
            entity_id: format!("org_invite_{suffix}"),
        },
        recipient: EmailRecipient {
            address: "member@example.com".to_owned(),
            display_name: None,
            locale: "en".to_owned(),
        },
        template: OrganizationInvitationTemplateV1 {
            organization_id: "org_test".to_owned(),
            organization_name: "Test Organization".to_owned(),
            invitation_id: format!("org_invite_{suffix}"),
            invitation_url: format!("https://example.test/invitations/secret-token-{suffix}"),
            inviter_display_name: Some("Operator".to_owned()),
            role_name: Some("Member".to_owned()),
            expires_at: now + Duration::days(1),
        },
        idempotency_key: format!("organization-invitation:org_invite_{suffix}"),
        correlation_id: format!("corr_notification_{suffix}"),
        causation_id: Some(format!("obs_invitation_{suffix}")),
        requested_by: Some("usr_test".to_owned()),
    }
}

fn access_request_notification(
    now: chrono::DateTime<Utc>,
    event: AccessRequestNotificationEvent,
) -> CreateAccessRequestNotificationIntent {
    let event_name = match event {
        AccessRequestNotificationEvent::Submitted => "submitted",
        AccessRequestNotificationEvent::Approved => "approved",
        AccessRequestNotificationEvent::Denied => "denied",
        AccessRequestNotificationEvent::Expiring => "expiring",
    };
    CreateAccessRequestNotificationIntent {
        source: IntentSource {
            module_id: "access-requests".to_owned(),
            entity_type: "access_request".to_owned(),
            entity_id: "ar_notification_1".to_owned(),
        },
        recipient: EmailRecipient {
            address: "requester@example.com".to_owned(),
            display_name: Some("Requester".to_owned()),
            locale: "en".to_owned(),
        },
        template: AccessRequestNotificationTemplateV1 {
            request_id: "ar_notification_1".to_owned(),
            organization_id: "org_test".to_owned(),
            event,
            role: AccessRequestRoleV1 {
                role_id: "role_member".to_owned(),
                display_name: Some("Member".to_owned()),
            },
            scope: AccessRequestScopeV1 {
                kind: "organization".to_owned(),
                id: "org_test".to_owned(),
                display_name: Some("Test Organization".to_owned()),
            },
            expires_at: Some(now + Duration::days(1)),
        },
        idempotency_key: format!("access-request:ar_notification_1:{event_name}"),
        correlation_id: "corr_access_request_notification_1".to_owned(),
        causation_id: Some(format!("access_request_notification_1:{event_name}")),
        requested_by: Some("usr_requester".to_owned()),
    }
}

fn invitation_render(request: &CreateTransactionalEmailIntent) -> RenderedTemplate {
    let subject = format!("Invitation to join {}", request.template.organization_name);
    let text = format!(
        "Accept invitation: {}\nExpires: {}",
        request.template.invitation_url,
        request.template.expires_at.to_rfc3339()
    );
    let html = format!(
        "<p><a href=\"{}\">Accept invitation</a></p>",
        request.template.invitation_url
    );
    RenderedTemplate {
        template_id: "organization-invitation".to_owned(),
        template_version: "v1".to_owned(),
        requested_locale: request.recipient.locale.clone(),
        resolved_locale: request.recipient.locale.clone(),
        fallback_used: false,
        renderer_identity: "lenso.notification-template.renderer/safe-sections@1".to_owned(),
        template_digest: format!("sha256:{}", "a".repeat(64)),
        content_digest: crate::snapshot::content_digest(&subject, &text, &html),
        subject,
        text,
        html,
    }
}

fn access_request_render(request: &CreateAccessRequestNotificationIntent) -> RenderedTemplate {
    let template_id = crate::public::access_request_template_id(request.template.event);
    let event = match request.template.event {
        AccessRequestNotificationEvent::Submitted => "submitted",
        AccessRequestNotificationEvent::Approved => "approved",
        AccessRequestNotificationEvent::Denied => "denied",
        AccessRequestNotificationEvent::Expiring => "expiring",
    };
    let subject = format!("Access request {event}");
    let text = format!("Request: {}", request.template.request_id);
    let html = format!("<p>Request: {}</p>", request.template.request_id);
    RenderedTemplate {
        template_id: template_id.to_owned(),
        template_version: "v1".to_owned(),
        requested_locale: request.recipient.locale.clone(),
        resolved_locale: request.recipient.locale.clone(),
        fallback_used: false,
        renderer_identity: "lenso.notification-template.renderer/safe-sections@1".to_owned(),
        template_digest: format!("sha256:{}", "b".repeat(64)),
        content_digest: crate::snapshot::content_digest(&subject, &text, &html),
        subject,
        text,
        html,
    }
}
