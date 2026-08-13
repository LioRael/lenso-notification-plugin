use crate::contracts::{
    DispatchOutcome, EMAIL_DISPATCH_OBSERVED_EVENT, EMAIL_RECEIPT_OBSERVED_EVENT,
    EmailDispatchObserved, EmailReceiptObserved, ORGANIZATION_INVITATION_ACCEPTED_EVENT,
    ORGANIZATION_INVITATION_REVOKED_EVENT, OrganizationInvitationLifecycle,
    RUNTIME_FUNCTION_TERMINAL_EVENT, ReceiptKind, RuntimeFunctionTerminal,
};
use crate::domain::RetryPolicy;
use async_trait::async_trait;
use lenso::host::outbox::{AppError, AppResult, ClaimedOutboxEvent, ErrorCode, EventHandler};
use lenso::host::runtime::AppContext;
use lenso::host::transaction::{DbPool, LinkedTransaction};
use sha2::{Digest as _, Sha256};

const DISPATCH_HANDLER: &str = "notification.apply-email-dispatch-observation.v1";
const RECEIPT_HANDLER: &str = "notification.apply-email-receipt.v1";
const TERMINAL_HANDLER: &str = "notification.apply-runtime-terminal.v1";
const INVITATION_ACCEPTED_HANDLER: &str = "notification.apply-invitation-accepted.v1";
const INVITATION_REVOKED_HANDLER: &str = "notification.apply-invitation-revoked.v1";
const EMAIL_RUNTIME_OWNER: &str = "lenso/email-delivery";
const EMAIL_DISPATCH_FUNCTION: &str = "lenso.email.dispatch.v1";

#[derive(Debug, Clone)]
pub struct NotificationEventHandler {
    app: AppContext,
    handler_name: &'static str,
    event_name: &'static str,
}

impl NotificationEventHandler {
    pub fn dispatch_observed(app: AppContext) -> Self {
        Self {
            app,
            handler_name: DISPATCH_HANDLER,
            event_name: EMAIL_DISPATCH_OBSERVED_EVENT,
        }
    }

    pub fn receipt_observed(app: AppContext) -> Self {
        Self {
            app,
            handler_name: RECEIPT_HANDLER,
            event_name: EMAIL_RECEIPT_OBSERVED_EVENT,
        }
    }

    pub fn runtime_terminal(app: AppContext) -> Self {
        Self {
            app,
            handler_name: TERMINAL_HANDLER,
            event_name: RUNTIME_FUNCTION_TERMINAL_EVENT,
        }
    }

    pub fn invitation_accepted(app: AppContext) -> Self {
        Self {
            app,
            handler_name: INVITATION_ACCEPTED_HANDLER,
            event_name: ORGANIZATION_INVITATION_ACCEPTED_EVENT,
        }
    }

    pub fn invitation_revoked(app: AppContext) -> Self {
        Self {
            app,
            handler_name: INVITATION_REVOKED_HANDLER,
            event_name: ORGANIZATION_INVITATION_REVOKED_EVENT,
        }
    }
}

#[async_trait]
impl EventHandler for NotificationEventHandler {
    fn handler_name(&self) -> &str {
        self.handler_name
    }

    fn event_name(&self) -> &str {
        self.event_name
    }

    async fn handle(&self, event: &ClaimedOutboxEvent) -> AppResult<()> {
        NotificationEventApplier::new(self.app.db.clone())
            .apply_for(self.event_name, event)
            .await
    }
}

/// Applies the same idempotent business transitions used by the Host Event
/// handlers. Keeping the database seam explicit makes the full delivery
/// lifecycle testable without manufacturing a private Host `AppContext`.
#[derive(Debug, Clone)]
pub struct NotificationEventApplier {
    db: DbPool,
}

impl NotificationEventApplier {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }

    pub async fn apply(&self, event: &ClaimedOutboxEvent) -> AppResult<()> {
        self.apply_for(event.event_name.as_str(), event).await
    }

    async fn apply_for(
        &self,
        expected_event_name: &str,
        event: &ClaimedOutboxEvent,
    ) -> AppResult<()> {
        if event.event_name != expected_event_name || event.event_version != 1 {
            return Err(AppError::new(
                ErrorCode::Validation,
                "Notification received an undeclared Event contract",
            ));
        }
        match expected_event_name {
            EMAIL_DISPATCH_OBSERVED_EVENT => {
                let payload: EmailDispatchObserved = decode_payload(event)?;
                validate_dispatch_observation(&payload)?;
                apply_dispatch_observation(&self.db, event, &payload).await
            }
            EMAIL_RECEIPT_OBSERVED_EVENT => {
                let payload: EmailReceiptObserved = decode_payload(event)?;
                validate_receipt(&payload)?;
                apply_receipt(&self.db, event, &payload).await
            }
            RUNTIME_FUNCTION_TERMINAL_EVENT => {
                let payload: RuntimeFunctionTerminal = decode_payload(event)?;
                apply_runtime_terminal(&self.db, event, &payload).await
            }
            ORGANIZATION_INVITATION_ACCEPTED_EVENT | ORGANIZATION_INVITATION_REVOKED_EVENT => {
                let payload: OrganizationInvitationLifecycle = decode_payload(event)?;
                apply_invitation_lifecycle(&self.db, event, &payload).await
            }
            _ => Err(AppError::new(
                ErrorCode::Validation,
                "Notification Event handler is misconfigured",
            )),
        }
    }
}

async fn apply_dispatch_observation(
    db: &DbPool,
    event: &ClaimedOutboxEvent,
    payload: &EmailDispatchObserved,
) -> AppResult<()> {
    let mut tx = LinkedTransaction::begin(db).await?;
    if claim_event(&mut tx, event, payload.observed_at).await? {
        tx.commit().await?;
        return Ok(());
    }
    let row = sqlx::query_as::<_, (String, i64, i32, i32, String, String, bool)>(
        r#"
        select deliveries.status, deliveries.revision, deliveries.attempt_count,
               deliveries.max_attempts, attempts.function_run_id, attempts.status,
               exists(select 1 from notification.receipts receipts where receipts.attempt_id = attempts.id)
        from notification.deliveries deliveries
        join notification.attempts attempts on attempts.delivery_id = deliveries.id
        where deliveries.id = $1 and attempts.id = $2
        for update of deliveries, attempts
        "#,
    )
    .bind(&payload.delivery_id)
    .bind(&payload.attempt_id)
    .fetch_optional(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| {
        AppError::new(
            ErrorCode::NotFound,
            "Email dispatch observation does not match a Notification attempt",
        )
    })?;
    let (
        delivery_status,
        revision,
        attempt_count,
        max_attempts,
        function_run_id,
        attempt_status,
        has_receipt,
    ) = row;
    if function_run_id != payload.function_run_id {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Email dispatch observation function run does not match",
        ));
    }
    if delivery_status != "attempting" {
        if late_observation_is_compatible(&delivery_status, has_receipt, payload.outcome) {
            absorb_late_dispatch_observation(&mut tx, payload).await?;
            tx.commit().await?;
            return Ok(());
        }
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Notification delivery is not waiting for a dispatch observation",
        ));
    }
    if attempt_status != "dispatching" {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Notification attempt already has a business observation",
        ));
    }

    match payload.outcome {
        DispatchOutcome::Accepted => {
            update_attempt(
                &mut tx,
                payload,
                "accepted",
                payload
                    .failure
                    .as_ref()
                    .map(|failure| failure.code.as_str()),
            )
            .await?;
            sqlx::query(
                r#"
                update notification.deliveries
                set status = 'accepted', revision = revision + 1, accepted_at = $3,
                    updated_at = $3
                where id = $1 and revision = $2 and status = 'attempting'
                "#,
            )
            .bind(&payload.delivery_id)
            .bind(revision)
            .bind(payload.observed_at)
            .execute(&mut **tx.sql())
            .await
            .map_err(map_sql_error)?;
            if let Some(receipt) = &payload.remote_receipt {
                insert_receipt(
                    &mut tx,
                    &payload.delivery_id,
                    &payload.attempt_id,
                    "accepted",
                    &receipt.source,
                    &receipt.remote_id,
                    &receipt.digest,
                    payload.observed_at,
                    payload.observed_at,
                )
                .await?;
            }
        }
        DispatchOutcome::TemporaryFailure => {
            update_attempt(
                &mut tx,
                payload,
                "temporary_failure",
                payload
                    .failure
                    .as_ref()
                    .map(|failure| failure.code.as_str()),
            )
            .await?;
            let policy = RetryPolicy {
                max_attempts,
                ..RetryPolicy::default()
            };
            if let Some(mut next_at) = policy.next_at(attempt_count, payload.observed_at) {
                if let Some(retry_after_ms) = payload
                    .failure
                    .as_ref()
                    .and_then(|failure| failure.retry_after_ms)
                {
                    let bounded_ms =
                        i64::try_from(retry_after_ms.min(86_400_000)).unwrap_or(86_400_000);
                    next_at = next_at
                        .max(payload.observed_at + chrono::Duration::milliseconds(bounded_ms));
                }
                sqlx::query(
                    r#"
                    update notification.deliveries
                    set status = 'retry_scheduled', revision = revision + 1,
                        next_attempt_at = $3, updated_at = $4
                    where id = $1 and revision = $2 and status = 'attempting'
                    "#,
                )
                .bind(&payload.delivery_id)
                .bind(revision)
                .bind(next_at)
                .bind(payload.observed_at)
                .execute(&mut **tx.sql())
                .await
                .map_err(map_sql_error)?;
                insert_retry_decision(
                    &mut tx,
                    &payload.delivery_id,
                    revision,
                    event,
                    "automatic",
                    "scheduled",
                    Some("temporary_failure"),
                    Some(next_at),
                    payload.observed_at,
                )
                .await?;
            } else {
                finalize_delivery(
                    &mut tx,
                    &payload.delivery_id,
                    revision,
                    "failed",
                    "retry_exhausted",
                    payload.observed_at,
                )
                .await?;
                insert_retry_decision(
                    &mut tx,
                    &payload.delivery_id,
                    revision,
                    event,
                    "automatic",
                    "rejected",
                    Some("retry_exhausted"),
                    None,
                    payload.observed_at,
                )
                .await?;
            }
        }
        DispatchOutcome::PermanentFailure => {
            update_attempt(
                &mut tx,
                payload,
                "permanent_failure",
                payload
                    .failure
                    .as_ref()
                    .map(|failure| failure.code.as_str()),
            )
            .await?;
            finalize_delivery(
                &mut tx,
                &payload.delivery_id,
                revision,
                "failed",
                "permanent_failure",
                payload.observed_at,
            )
            .await?;
        }
        DispatchOutcome::DeliveryUnknown => {
            update_attempt(
                &mut tx,
                payload,
                "delivery_unknown",
                payload
                    .failure
                    .as_ref()
                    .map(|failure| failure.code.as_str()),
            )
            .await?;
            finalize_delivery(
                &mut tx,
                &payload.delivery_id,
                revision,
                "delivery_unknown",
                "ambiguous_external_effect",
                payload.observed_at,
            )
            .await?;
        }
    }
    tx.commit().await
}

fn late_observation_is_compatible(
    delivery_status: &str,
    has_receipt: bool,
    outcome: DispatchOutcome,
) -> bool {
    has_receipt
        && ((delivery_status == "delivered" && outcome == DispatchOutcome::Accepted)
            || (delivery_status == "failed" && outcome == DispatchOutcome::PermanentFailure))
}

async fn apply_receipt(
    db: &DbPool,
    event: &ClaimedOutboxEvent,
    payload: &EmailReceiptObserved,
) -> AppResult<()> {
    let mut tx = LinkedTransaction::begin(db).await?;
    if claim_event(&mut tx, event, payload.observed_at).await? {
        tx.commit().await?;
        return Ok(());
    }
    let kind = match payload.kind {
        ReceiptKind::Delivered => "delivered",
        ReceiptKind::Bounced => "bounced",
        ReceiptKind::Rejected => "rejected",
    };
    if let Some(existing) = sqlx::query_scalar::<_, String>(
        "select digest from notification.receipts where source = $1 and remote_id = $2 and kind = $3",
    )
    .bind(&payload.source)
    .bind(&payload.remote_id)
    .bind(kind)
    .fetch_optional(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?
    {
        if existing != payload.digest {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "Email receipt identity was replayed with a different digest",
            ));
        }
        tx.commit().await?;
        return Ok(());
    }
    let row = sqlx::query_as::<_, (String, i64, String, String)>(
        r#"
        select deliveries.status, deliveries.revision, attempts.function_run_id, attempts.status
        from notification.deliveries deliveries
        join notification.attempts attempts on attempts.delivery_id = deliveries.id
        where deliveries.id = $1 and attempts.id = $2
        for update of deliveries, attempts
        "#,
    )
    .bind(&payload.delivery_id)
    .bind(&payload.attempt_id)
    .fetch_optional(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| {
        AppError::new(
            ErrorCode::NotFound,
            "Email receipt does not match a Notification attempt",
        )
    })?;
    let (status, revision, function_run_id, _attempt_status) = row;
    if function_run_id != payload.function_run_id {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Email receipt function run does not match",
        ));
    }
    if !matches!(status.as_str(), "attempting" | "accepted") {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Email receipt would regress a terminal Notification delivery",
        ));
    }
    insert_receipt(
        &mut tx,
        &payload.delivery_id,
        &payload.attempt_id,
        kind,
        &payload.source,
        &payload.remote_id,
        &payload.digest,
        payload.observed_at,
        event.occurred_at,
    )
    .await?;
    match payload.kind {
        ReceiptKind::Delivered => {
            sqlx::query(
                "update notification.attempts set status = 'accepted', completed_at = coalesce(completed_at, $2) where id = $1",
            )
            .bind(&payload.attempt_id)
            .bind(payload.observed_at)
            .execute(&mut **tx.sql())
            .await
            .map_err(map_sql_error)?;
            sqlx::query(
                r#"
                update notification.deliveries
                set status = 'delivered', revision = revision + 1,
                    accepted_at = coalesce(accepted_at, $3), delivered_at = $3,
                    final_at = $3, final_reason = 'authoritative_delivery_receipt', updated_at = $3
                where id = $1 and revision = $2 and status in ('attempting', 'accepted')
                "#,
            )
            .bind(&payload.delivery_id)
            .bind(revision)
            .bind(payload.observed_at)
            .execute(&mut **tx.sql())
            .await
            .map_err(map_sql_error)?;
        }
        ReceiptKind::Bounced | ReceiptKind::Rejected => {
            sqlx::query(
                "update notification.attempts set status = 'permanent_failure', completed_at = coalesce(completed_at, $2) where id = $1",
            )
            .bind(&payload.attempt_id)
            .bind(payload.observed_at)
            .execute(&mut **tx.sql())
            .await
            .map_err(map_sql_error)?;
            finalize_delivery(
                &mut tx,
                &payload.delivery_id,
                revision,
                "failed",
                kind,
                payload.observed_at,
            )
            .await?;
        }
    }
    tx.commit().await
}

async fn apply_runtime_terminal(
    db: &DbPool,
    event: &ClaimedOutboxEvent,
    payload: &RuntimeFunctionTerminal,
) -> AppResult<()> {
    validate_runtime_terminal(payload)?;
    let mut tx = LinkedTransaction::begin(db).await?;
    if claim_event(&mut tx, event, event.occurred_at).await? {
        tx.commit().await?;
        return Ok(());
    }
    let row = sqlx::query_as::<_, (String, String, i64)>(
        r#"
        select attempts.id, deliveries.id, deliveries.revision
        from notification.attempts attempts
        join notification.deliveries deliveries on deliveries.id = attempts.delivery_id
        where attempts.function_run_id = $1
          and attempts.status = 'dispatching'
          and deliveries.status = 'attempting'
        for update of attempts, deliveries
        "#,
    )
    .bind(&payload.function_run_id)
    .fetch_optional(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    let Some((attempt_id, delivery_id, revision)) = row else {
        tx.commit().await?;
        return Ok(());
    };
    sqlx::query(
        r#"
        update notification.attempts
        set status = 'delivery_unknown', failure_code = $2,
            failure_classification = $3, completed_at = $4
        where id = $1 and status = 'dispatching'
        "#,
    )
    .bind(attempt_id)
    .bind(bounded(&payload.failure_code, 160))
    .bind(&payload.failure_classification)
    .bind(event.occurred_at)
    .execute(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    finalize_delivery(
        &mut tx,
        &delivery_id,
        revision,
        "delivery_unknown",
        "provider_runtime_terminal_without_business_observation",
        event.occurred_at,
    )
    .await?;
    tx.commit().await
}

fn validate_runtime_terminal(payload: &RuntimeFunctionTerminal) -> AppResult<()> {
    if payload.owner_module != EMAIL_RUNTIME_OWNER
        || payload.function_name != EMAIL_DISPATCH_FUNCTION
        || payload.terminal_state != "dead"
        || !matches!(
            payload.failure_classification.as_str(),
            "permanent_failure" | "retry_exhausted"
        )
    {
        return Err(AppError::new(
            ErrorCode::Validation,
            "Runtime terminal observation is not for the Email dispatch contract",
        ));
    }
    Ok(())
}

async fn apply_invitation_lifecycle(
    db: &DbPool,
    event: &ClaimedOutboxEvent,
    payload: &OrganizationInvitationLifecycle,
) -> AppResult<()> {
    let lifecycle = if event.event_name == ORGANIZATION_INVITATION_ACCEPTED_EVENT {
        "accepted"
    } else {
        "revoked"
    };
    let mut tx = LinkedTransaction::begin(db).await?;
    if claim_event(&mut tx, event, payload.observed_at).await? {
        tx.commit().await?;
        return Ok(());
    }
    sqlx::query(
        r#"
        insert into notification.source_lifecycle_events (
            event_id, source_module, source_entity_type, source_entity_id,
            lifecycle, observed_at, recorded_at
        ) values ($1, 'organization', 'organization_invitation', $2, $3, $4, $5)
        "#,
    )
    .bind(&event.id)
    .bind(&payload.invitation_id)
    .bind(lifecycle)
    .bind(payload.observed_at)
    .bind(event.occurred_at)
    .execute(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    sqlx::query(
        r#"
        update notification.deliveries deliveries
        set status = 'failed', revision = revision + 1, next_attempt_at = null,
            final_at = $3, final_reason = $4, updated_at = $3
        from notification.intents intents
        where deliveries.intent_id = intents.id
          and intents.source_module = 'organization'
          and intents.source_entity_type = 'organization_invitation'
          and intents.source_entity_id = $1
          and deliveries.status in ('queued', 'retry_scheduled')
          and intents.requested_at <= $2
        "#,
    )
    .bind(&payload.invitation_id)
    .bind(payload.observed_at)
    .bind(event.occurred_at)
    .bind(format!("source_invitation_{lifecycle}"))
    .execute(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    tx.commit().await
}

async fn claim_event(
    tx: &mut LinkedTransaction<'_>,
    event: &ClaimedOutboxEvent,
    consumed_at: chrono::DateTime<chrono::Utc>,
) -> AppResult<bool> {
    let digest = event_digest(event)?;
    let inserted = sqlx::query_scalar::<_, String>(
        r#"
        insert into notification.consumed_events (event_id, event_name, event_digest, consumed_at)
        values ($1, $2, $3, $4)
        on conflict (event_id) do nothing
        returning event_id
        "#,
    )
    .bind(&event.id)
    .bind(&event.event_name)
    .bind(&digest)
    .bind(consumed_at)
    .fetch_optional(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    if inserted.is_some() {
        return Ok(false);
    }
    let existing = sqlx::query_scalar::<_, String>(
        "select event_digest from notification.consumed_events where event_id = $1",
    )
    .bind(&event.id)
    .fetch_one(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    if existing != digest {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Notification Event id was replayed with different content",
        ));
    }
    Ok(true)
}

async fn update_attempt(
    tx: &mut LinkedTransaction<'_>,
    payload: &EmailDispatchObserved,
    status: &str,
    failure_code: Option<&str>,
) -> AppResult<()> {
    let (remote_id, remote_source, remote_digest) =
        payload
            .remote_receipt
            .as_ref()
            .map_or((None, None, None), |receipt| {
                (
                    Some(receipt.remote_id.as_str()),
                    Some(receipt.source.as_str()),
                    Some(receipt.digest.as_str()),
                )
            });
    sqlx::query(
        r#"
        update notification.attempts
        set status = $2, provider = $3, remote_receipt_id = $4,
            remote_receipt_source = $5, remote_receipt_digest = $6,
            failure_code = $7, failure_classification = $8, completed_at = $9
        where id = $1 and status = 'dispatching'
        "#,
    )
    .bind(&payload.attempt_id)
    .bind(status)
    .bind(bounded(&payload.provider, 160))
    .bind(remote_id.map(|value| bounded(value, 320)))
    .bind(remote_source.map(|value| bounded(value, 160)))
    .bind(remote_digest)
    .bind(failure_code.map(|value| bounded(value, 160)))
    .bind(
        payload
            .failure
            .as_ref()
            .map(|failure| bounded(&failure.classification, 160)),
    )
    .bind(payload.observed_at)
    .execute(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    Ok(())
}

/// Provider outcome and receipt Effects are committed together but delivered
/// independently. A receipt can therefore finalize the delivery before the
/// causally earlier dispatch observation arrives. Preserve the final state and
/// only fill bounded attempt metadata; never regress delivery or attempt state.
async fn absorb_late_dispatch_observation(
    tx: &mut LinkedTransaction<'_>,
    payload: &EmailDispatchObserved,
) -> AppResult<()> {
    let (remote_id, remote_source, remote_digest) =
        payload
            .remote_receipt
            .as_ref()
            .map_or((None, None, None), |receipt| {
                (
                    Some(bounded(&receipt.remote_id, 320)),
                    Some(bounded(&receipt.source, 160)),
                    Some(receipt.digest.as_str()),
                )
            });
    sqlx::query(
        r#"
        update notification.attempts
        set provider = coalesce(provider, $2),
            remote_receipt_id = coalesce(remote_receipt_id, $3),
            remote_receipt_source = coalesce(remote_receipt_source, $4),
            remote_receipt_digest = coalesce(remote_receipt_digest, $5),
            failure_code = coalesce(failure_code, $6),
            failure_classification = coalesce(failure_classification, $7),
            completed_at = coalesce(completed_at, $8)
        where id = $1 and function_run_id = $9
        "#,
    )
    .bind(&payload.attempt_id)
    .bind(bounded(&payload.provider, 160))
    .bind(remote_id)
    .bind(remote_source)
    .bind(remote_digest)
    .bind(
        payload
            .failure
            .as_ref()
            .map(|failure| bounded(&failure.code, 160)),
    )
    .bind(
        payload
            .failure
            .as_ref()
            .map(|failure| bounded(&failure.classification, 160)),
    )
    .bind(payload.observed_at)
    .bind(&payload.function_run_id)
    .execute(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_receipt(
    tx: &mut LinkedTransaction<'_>,
    delivery_id: &str,
    attempt_id: &str,
    kind: &str,
    source: &str,
    remote_id: &str,
    digest: &str,
    observed_at: chrono::DateTime<chrono::Utc>,
    recorded_at: chrono::DateTime<chrono::Utc>,
) -> AppResult<()> {
    let id = stable_id("ntf_rcp", &format!("{source}:{remote_id}:{kind}"));
    sqlx::query(
        r#"
        insert into notification.receipts (
            id, delivery_id, attempt_id, kind, source, remote_id, digest, observed_at, recorded_at
        ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(id)
    .bind(delivery_id)
    .bind(attempt_id)
    .bind(kind)
    .bind(bounded(source, 160))
    .bind(bounded(remote_id, 320))
    .bind(digest)
    .bind(observed_at)
    .bind(recorded_at)
    .execute(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_retry_decision(
    tx: &mut LinkedTransaction<'_>,
    delivery_id: &str,
    revision: i64,
    event: &ClaimedOutboxEvent,
    kind: &str,
    decision: &str,
    reason: Option<&str>,
    scheduled_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> AppResult<()> {
    sqlx::query(
        r#"
        insert into notification.retry_requests (
            id, delivery_id, kind, requested_by, source_revision, idempotency_key,
            decision, reason, scheduled_at, created_at
        ) values ($1, $2, $3, null, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(stable_id("ntf_rty", &event.id))
    .bind(delivery_id)
    .bind(kind)
    .bind(revision)
    .bind(&event.id)
    .bind(decision)
    .bind(reason)
    .bind(scheduled_at)
    .bind(created_at)
    .execute(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    Ok(())
}

async fn finalize_delivery(
    tx: &mut LinkedTransaction<'_>,
    delivery_id: &str,
    revision: i64,
    status: &str,
    reason: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> AppResult<()> {
    let result = sqlx::query(
        r#"
        update notification.deliveries
        set status = $3, revision = revision + 1, next_attempt_at = null,
            final_at = $4, final_reason = $5, updated_at = $4
        where id = $1 and revision = $2 and status in ('attempting', 'accepted')
        "#,
    )
    .bind(delivery_id)
    .bind(revision)
    .bind(status)
    .bind(now)
    .bind(reason)
    .execute(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    if result.rows_affected() != 1 {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Notification delivery changed before finalization",
        ));
    }
    Ok(())
}

fn decode_payload<T: serde::de::DeserializeOwned>(event: &ClaimedOutboxEvent) -> AppResult<T> {
    serde_json::from_value(event.payload.clone()).map_err(|error| {
        AppError::new(
            ErrorCode::Validation,
            "Notification Event payload is invalid",
        )
        .with_source(error)
    })
}

fn event_digest(event: &ClaimedOutboxEvent) -> AppResult<String> {
    let value = serde_json::json!({
        "id": event.id,
        "name": event.event_name,
        "version": event.event_version,
        "source": event.source_module,
        "aggregateId": event.aggregate_id,
        "payload": event.payload,
    });
    let encoded = serde_json::to_vec(&value).map_err(|error| {
        AppError::new(ErrorCode::Internal, "Notification Event cannot be hashed").with_source(error)
    })?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(encoded))))
}

fn validate_dispatch_observation(payload: &EmailDispatchObserved) -> AppResult<()> {
    for (field, value, limit) in [
        ("provider", payload.provider.as_str(), 160),
        ("deliveryId", payload.delivery_id.as_str(), 160),
        ("attemptId", payload.attempt_id.as_str(), 160),
        ("functionRunId", payload.function_run_id.as_str(), 160),
    ] {
        if value.is_empty() || value.chars().count() > limit {
            return Err(AppError::new(
                ErrorCode::Validation,
                format!("Email dispatch observation {field} is invalid"),
            ));
        }
    }
    if payload.outcome != DispatchOutcome::Accepted && payload.failure.is_none() {
        return Err(AppError::new(
            ErrorCode::Validation,
            "Email failure observation requires sanitized failure metadata",
        ));
    }
    if let Some(receipt) = &payload.remote_receipt {
        validate_digest(&receipt.digest)?;
        if receipt.remote_id.chars().count() > 320 || receipt.source.chars().count() > 160 {
            return Err(AppError::new(
                ErrorCode::Validation,
                "Email remote receipt metadata exceeds bounds",
            ));
        }
    }
    Ok(())
}

fn validate_receipt(payload: &EmailReceiptObserved) -> AppResult<()> {
    validate_digest(&payload.digest)?;
    if payload.remote_id.is_empty()
        || payload.remote_id.chars().count() > 320
        || payload.source.is_empty()
        || payload.source.chars().count() > 160
    {
        return Err(AppError::new(
            ErrorCode::Validation,
            "Email receipt identity is invalid",
        ));
    }
    Ok(())
}

fn validate_digest(value: &str) -> AppResult<()> {
    if value.strip_prefix("sha256:").is_none_or(|digest| {
        digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }) {
        return Err(AppError::new(
            ErrorCode::Validation,
            "Email evidence digest is invalid",
        ));
    }
    Ok(())
}

fn bounded(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn stable_id(prefix: &str, input: &str) -> String {
    let digest = hex::encode(Sha256::digest(input.as_bytes()));
    format!("{prefix}_{}", &digest[..32])
}

fn map_sql_error(error: sqlx::Error) -> AppError {
    AppError::new(
        ErrorCode::Internal,
        "Notification Event storage operation failed",
    )
    .with_source(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_distinguishes_accepted_from_delivery() {
        let observed = EmailDispatchObserved {
            delivery_id: "ntf_dlv_1".to_owned(),
            attempt_id: "ntf_att_1".to_owned(),
            function_run_id: "ntf_run_1".to_owned(),
            outcome: DispatchOutcome::Accepted,
            provider: "smtp".to_owned(),
            observed_at: chrono::Utc::now(),
            remote_receipt: None,
            failure: None,
        };
        validate_dispatch_observation(&observed).expect("SMTP acceptance is a known outcome");
        assert_ne!(
            serde_json::to_value(observed).expect("serialized")["outcome"],
            "delivered"
        );
    }

    #[test]
    fn late_dispatch_absorption_requires_receipt_and_compatible_terminal_state() {
        assert!(late_observation_is_compatible(
            "delivered",
            true,
            DispatchOutcome::Accepted
        ));
        assert!(late_observation_is_compatible(
            "failed",
            true,
            DispatchOutcome::PermanentFailure
        ));
        assert!(!late_observation_is_compatible(
            "delivered",
            true,
            DispatchOutcome::TemporaryFailure
        ));
        assert!(!late_observation_is_compatible(
            "delivered",
            true,
            DispatchOutcome::DeliveryUnknown
        ));
        assert!(!late_observation_is_compatible(
            "delivered",
            false,
            DispatchOutcome::Accepted
        ));
    }

    #[test]
    fn runtime_terminal_is_bound_to_email_delivery_owner_and_function() {
        let valid = RuntimeFunctionTerminal {
            failure_classification: "retry_exhausted".to_owned(),
            failure_code: "provider_unavailable".to_owned(),
            function_name: EMAIL_DISPATCH_FUNCTION.to_owned(),
            function_run_id: "ntf_run_1".to_owned(),
            owner_module: EMAIL_RUNTIME_OWNER.to_owned(),
            terminal_state: "dead".to_owned(),
        };
        validate_runtime_terminal(&valid).expect("valid terminal");
        let mut wrong_owner = valid.clone();
        wrong_owner.owner_module = "lenso/another-provider".to_owned();
        assert_eq!(
            validate_runtime_terminal(&wrong_owner)
                .expect_err("owner rejected")
                .code,
            ErrorCode::Validation
        );
        let mut wrong_function = valid;
        wrong_function.function_name = "lenso.email.receipt-check.v1".to_owned();
        assert_eq!(
            validate_runtime_terminal(&wrong_function)
                .expect_err("function rejected")
                .code,
            ErrorCode::Validation
        );
    }
}
