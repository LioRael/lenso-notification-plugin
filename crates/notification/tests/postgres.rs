use chrono::{Duration, Utc};
use lenso::host::outbox::ClaimedOutboxEvent;
use notification::contracts::{
    DispatchOutcome, EMAIL_DISPATCH_OBSERVED_EVENT, EMAIL_RECEIPT_OBSERVED_EVENT,
    EmailDispatchObserved, EmailDispatchRequested, EmailReceiptObserved, ReceiptKind,
    RemoteReceiptSummary, SanitizedFailure,
};
use notification::domain::DeliveryStatus;
use notification::events::NotificationEventApplier;
use notification::public::{
    CreateTransactionalEmailIntent, EmailRecipient, IntentSource, OrganizationInvitationTemplateV1,
    create_transactional_email_intent_in_tx_with_protector,
};
use notification::repository::PostgresNotificationRepository;
use notification::runtime::dispatch_one_due_with_protector;
use notification::snapshot::TestSnapshotProtector;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn public_intent_is_atomic_and_business_idempotent_when_postgres_is_configured() {
    let database_url =
        std::env::var("LENSO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"));
    let Ok(database_url) = database_url else {
        eprintln!("skipping Postgres acceptance: LENSO_TEST_DATABASE_URL is not configured");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("connect test Postgres");
    sqlx::raw_sql(include_str!(
        "../migrations/0001_create_notification_schema.sql"
    ))
    .execute(&pool)
    .await
    .expect("apply Notification migration");
    ensure_test_outbox(&pool).await;
    sqlx::raw_sql(
        r#"
        truncate table notification.source_lifecycle_events, notification.consumed_events,
            notification.retry_requests, notification.receipts, notification.attempts,
            notification.deliveries, notification.intents, notification.render_snapshots,
            notification.template_releases restart identity cascade
        "#,
    )
    .execute(&pool)
    .await
    .expect("clean Notification schema");

    let now = Utc::now();
    let request = request(now);
    let mut first_tx = lenso::host::transaction::LinkedTransaction::begin(&pool)
        .await
        .expect("begin");
    let first = create_transactional_email_intent_in_tx_with_protector(
        &mut first_tx,
        &request,
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect("create intent");
    first_tx.commit().await.expect("commit");
    assert_eq!(first.status, DeliveryStatus::Queued);
    assert!(!first.idempotent_replay);

    let mut replay_tx = lenso::host::transaction::LinkedTransaction::begin(&pool)
        .await
        .expect("begin replay");
    let replay = create_transactional_email_intent_in_tx_with_protector(
        &mut replay_tx,
        &request,
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
    let mut conflict_tx = lenso::host::transaction::LinkedTransaction::begin(&pool)
        .await
        .expect("begin conflict");
    let conflict = create_transactional_email_intent_in_tx_with_protector(
        &mut conflict_tx,
        &changed,
        now,
        &TestSnapshotProtector,
    )
    .await
    .expect_err("same key with changed input must conflict");
    assert_eq!(conflict.code, lenso::host::outbox::ErrorCode::Conflict);
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
    .expect("scan ciphertext");
    assert_eq!(leaked, 0);

    let first_claim = dispatch_one_due_with_protector(&pool, &TestSnapshotProtector, now)
        .await
        .expect("claim first attempt")
        .expect("queued delivery is due");
    assert_eq!(first_claim.delivery_id, first.delivery_id);
    let (dispatch_name, dispatch_payload, dispatch_headers): (String, Value, Value) =
        sqlx::query_as(
            "select event_name, payload, headers from platform.outbox where aggregate_id = $1 order by created_at desc limit 1",
        )
        .bind(&first.delivery_id)
        .fetch_one(&pool)
        .await
        .expect("read dispatch Event");
    assert_eq!(dispatch_name, "lenso.email.dispatch-requested.v1");
    let dispatch: EmailDispatchRequested =
        serde_json::from_value(dispatch_payload).expect("decode dispatch contract");
    assert_eq!(dispatch.function_run_id, first_claim.function_run_id);
    assert_eq!(dispatch.recipient.address, "member@example.com");
    assert!(dispatch.message.text.contains("secret-token"));
    assert_eq!(dispatch_headers["log_payload"], false);

    let applier = NotificationEventApplier::new(pool.clone());
    let first_failed_at = now + Duration::seconds(1);
    let temporary_failure = EmailDispatchObserved {
        delivery_id: first.delivery_id.clone(),
        attempt_id: first_claim.attempt_id.clone(),
        function_run_id: first_claim.function_run_id.clone(),
        outcome: DispatchOutcome::TemporaryFailure,
        provider: "fake".to_owned(),
        observed_at: first_failed_at,
        remote_receipt: None,
        failure: Some(SanitizedFailure {
            code: "provider_rate_limited".to_owned(),
            classification: "temporary_failure".to_owned(),
            retry_after_ms: Some(120_000),
        }),
    };
    let failed_event = event(
        "evt_dispatch_failed_test",
        EMAIL_DISPATCH_OBSERVED_EVENT,
        &temporary_failure,
        first_failed_at,
    );
    applier
        .apply(&failed_event)
        .await
        .expect("schedule business retry");
    applier
        .apply(&failed_event)
        .await
        .expect("replay failure observation idempotently");

    let retry_at: chrono::DateTime<Utc> =
        sqlx::query_scalar("select next_attempt_at from notification.deliveries where id = $1")
            .bind(&first.delivery_id)
            .fetch_one(&pool)
            .await
            .expect("read retry schedule");
    assert_eq!(retry_at, first_failed_at + Duration::seconds(120));
    assert!(
        dispatch_one_due_with_protector(
            &pool,
            &TestSnapshotProtector,
            first_failed_at + Duration::seconds(119),
        )
        .await
        .expect("check early retry")
        .is_none(),
        "provider retry-after hint must prevent an early retry"
    );

    let second_claim = dispatch_one_due_with_protector(
        &pool,
        &TestSnapshotProtector,
        first_failed_at + Duration::seconds(120),
    )
    .await
    .expect("claim second attempt")
    .expect("retry is due");
    assert_ne!(second_claim.attempt_id, first_claim.attempt_id);
    assert_ne!(second_claim.function_run_id, first_claim.function_run_id);

    let accepted_at = retry_at + Duration::seconds(1);
    applier
        .apply(&event(
            "evt_dispatch_accepted_test",
            EMAIL_DISPATCH_OBSERVED_EVENT,
            &EmailDispatchObserved {
                delivery_id: first.delivery_id.clone(),
                attempt_id: second_claim.attempt_id.clone(),
                function_run_id: second_claim.function_run_id.clone(),
                outcome: DispatchOutcome::Accepted,
                provider: "fake".to_owned(),
                observed_at: accepted_at,
                remote_receipt: Some(RemoteReceiptSummary {
                    source: "fake".to_owned(),
                    remote_id: "remote-delivered-test".to_owned(),
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
            "evt_receipt_delivered_test",
            EMAIL_RECEIPT_OBSERVED_EVENT,
            &EmailReceiptObserved {
                delivery_id: first.delivery_id.clone(),
                attempt_id: second_claim.attempt_id.clone(),
                function_run_id: second_claim.function_run_id.clone(),
                kind: ReceiptKind::Delivered,
                source: "fake".to_owned(),
                observed_at: delivered_at,
                remote_id: "remote-delivered-test".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
            },
            delivered_at,
        ))
        .await
        .expect("record authoritative delivered receipt");

    let detail = PostgresNotificationRepository::from_pool(pool.clone())
        .get_delivery(&first.delivery_id)
        .await
        .expect("load Console detail")
        .expect("delivery exists");
    assert_eq!(detail.delivery.status, "delivered");
    assert_eq!(detail.delivery.attempt_count, 2);
    assert_eq!(detail.attempts.len(), 2);
    assert_eq!(detail.attempts[0].status, "temporary_failure");
    assert_eq!(detail.attempts[1].status, "accepted");
    assert_eq!(detail.receipts.len(), 2);
    assert_eq!(detail.receipts[0].kind, "accepted");
    assert_eq!(detail.receipts[1].kind, "delivered");
    assert_eq!(detail.retry_requests.len(), 1);
    let console_json = serde_json::to_string(&detail).expect("serialize Console detail");
    assert!(!console_json.contains("member@example.com"));
    assert!(!console_json.contains("secret-token"));
}

fn event(
    id: &str,
    name: &str,
    payload: &impl Serialize,
    occurred_at: chrono::DateTime<Utc>,
) -> ClaimedOutboxEvent {
    ClaimedOutboxEvent {
        id: id.to_owned(),
        event_name: name.to_owned(),
        event_version: 1,
        source_module: "lenso/email-delivery".to_owned(),
        aggregate_type: "notification.delivery".to_owned(),
        aggregate_id: "notification-test".to_owned(),
        correlation_id: "corr_notification_test".to_owned(),
        causation_id: None,
        occurred_at,
        payload: serde_json::to_value(payload).expect("encode Event fixture"),
        headers: json!({}),
        attempts: 1,
        max_attempts: 4,
    }
}

async fn ensure_test_outbox(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        r#"
        create schema if not exists platform;
        create table if not exists platform.outbox (
            id text primary key,
            event_name text not null,
            event_version integer not null,
            source_module text not null,
            aggregate_type text not null,
            aggregate_id text not null,
            correlation_id text not null,
            causation_id text,
            occurred_at timestamptz not null,
            payload jsonb not null,
            headers jsonb not null default '{}'::jsonb,
            status text not null default 'pending',
            attempts integer not null default 0,
            max_attempts integer not null default 3,
            available_at timestamptz not null default now(),
            locked_at timestamptz,
            locked_by text,
            published_at timestamptz,
            last_error text,
            created_at timestamptz not null default now()
        );
        "#,
    )
    .execute(pool)
    .await
    .expect("ensure Host Outbox test contract");
    sqlx::query("delete from platform.outbox where source_module = 'lenso/notification'")
        .execute(pool)
        .await
        .expect("clean Notification Outbox Events");
}

fn request(now: chrono::DateTime<Utc>) -> CreateTransactionalEmailIntent {
    CreateTransactionalEmailIntent {
        source: IntentSource {
            module_id: "organization".to_owned(),
            entity_type: "organization_invitation".to_owned(),
            entity_id: "org_invite_test".to_owned(),
        },
        recipient: EmailRecipient {
            address: "member@example.com".to_owned(),
            display_name: None,
            locale: "en".to_owned(),
        },
        template: OrganizationInvitationTemplateV1 {
            organization_id: "org_test".to_owned(),
            organization_name: "Test Organization".to_owned(),
            invitation_id: "org_invite_test".to_owned(),
            invitation_url: "https://example.test/invitations/secret-token".to_owned(),
            inviter_display_name: Some("Operator".to_owned()),
            role_name: Some("Member".to_owned()),
            expires_at: now + Duration::days(1),
        },
        idempotency_key: "organization-invitation:org_invite_test".to_owned(),
        correlation_id: "corr_notification_test".to_owned(),
        causation_id: Some("evt_invitation_test".to_owned()),
        requested_by: Some("usr_test".to_owned()),
    }
}
