use crate::contracts::{
    DispatchContext, DispatchMessage, DispatchRecipient, EMAIL_DISPATCH_REQUESTED_EVENT,
    EmailChannel, EmailDispatchRequested,
};
use crate::snapshot::{EnvironmentSnapshotProtector, ProtectedValue, SnapshotProtector};
use async_trait::async_trait;
use lenso::host::runtime::{
    AppContext, AppError, AppResult, ErrorCode, ExecutionContext, FunctionHandler,
};
use lenso::host::transaction::{DbPool, LinkedTransaction, OutboxEvent};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub const DISPATCH_DUE_FUNCTION: &str = "notification.dispatch-due.v1";
pub const DISPATCH_QUEUE: &str = "notification";

#[derive(Debug, Clone)]
pub struct DispatchDueDeliveries {
    app: AppContext,
}

impl DispatchDueDeliveries {
    pub fn new(app: AppContext) -> Self {
        Self { app }
    }
}

#[async_trait]
impl FunctionHandler for DispatchDueDeliveries {
    async fn call(&self, _context: ExecutionContext, input: Value) -> AppResult<Value> {
        let limit = input
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(25)
            .clamp(1, 100);
        let protector = EnvironmentSnapshotProtector::from_env()?;
        let now = self.app.clock.now();
        let mut claimed = Vec::new();
        for _ in 0..limit {
            let Some(attempt) =
                dispatch_one_due_with_protector(&self.app.db, &protector, now).await?
            else {
                break;
            };
            claimed.push(json!({
                "deliveryId": attempt.delivery_id,
                "attemptId": attempt.attempt_id,
                "functionRunId": attempt.function_run_id,
            }));
        }
        let count = claimed.len();
        Ok(json!({ "claimed": claimed, "count": count }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchClaim {
    pub delivery_id: String,
    pub attempt_id: String,
    pub function_run_id: String,
}

#[allow(clippy::too_many_arguments)]
type DueRow = (
    String,
    i64,
    i32,
    i32,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

/// Claims one due business delivery and publishes its immutable dispatch Event
/// in the same database transaction.
///
/// The runtime handler uses the environment-backed protector. This explicit
/// seam lets host acceptance tests inject a deterministic protector without
/// mutating process-wide secret configuration.
pub async fn dispatch_one_due_with_protector(
    db: &DbPool,
    protector: &dyn SnapshotProtector,
    now: chrono::DateTime<chrono::Utc>,
) -> AppResult<Option<DispatchClaim>> {
    let mut tx = LinkedTransaction::begin(db).await?;
    let row = sqlx::query_as::<_, DueRow>(
        r#"
        select deliveries.id, deliveries.revision, deliveries.attempt_count, deliveries.max_attempts,
               intents.correlation_id, intents.causation_id, intents.recipient_ciphertext,
               intents.recipient_key_ref, intents.locale, snapshots.subject_ciphertext,
               snapshots.text_ciphertext, snapshots.html_ciphertext, snapshots.protection_key_ref,
               snapshots.content_digest, templates.template_id, templates.version
        from notification.deliveries deliveries
        join notification.intents intents on intents.id = deliveries.intent_id
        join notification.render_snapshots snapshots on snapshots.id = intents.snapshot_id
        join notification.template_releases templates on templates.id = snapshots.template_release_id
        where deliveries.status in ('queued', 'retry_scheduled')
          and deliveries.next_attempt_at <= $1
          and deliveries.attempt_count < deliveries.max_attempts
        order by deliveries.next_attempt_at asc, deliveries.id asc
        for update of deliveries skip locked
        limit 1
        "#,
    )
    .bind(now)
    .fetch_optional(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    let Some((
        delivery_id,
        revision,
        attempt_count,
        max_attempts,
        correlation_id,
        causation_id,
        recipient_ciphertext,
        recipient_key_ref,
        locale,
        subject_ciphertext,
        text_ciphertext,
        html_ciphertext,
        protection_key_ref,
        message_digest,
        template_id,
        template_version,
    )) = row
    else {
        tx.commit().await?;
        return Ok(None);
    };
    let sequence = attempt_count + 1;
    if sequence > max_attempts {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Notification delivery exhausted before dispatch",
        ));
    }
    let attempt_id = stable_id("ntf_att", &format!("{delivery_id}:{sequence}"));
    let function_run_id = stable_id("ntf_run", &attempt_id);
    let dispatch_event_id = stable_id("evt", &format!("dispatch:{attempt_id}"));

    let reveal = |ciphertext: String, key_reference: String| {
        protector.reveal(&ProtectedValue {
            ciphertext,
            key_reference,
        })
    };
    let recipient = reveal(recipient_ciphertext, recipient_key_ref)?;
    let subject = reveal(subject_ciphertext, protection_key_ref.clone())?;
    let text = reveal(text_ciphertext, protection_key_ref.clone())?;
    let html = reveal(html_ciphertext, protection_key_ref)?;
    let payload = EmailDispatchRequested {
        delivery_id: delivery_id.clone(),
        attempt_id: attempt_id.clone(),
        function_run_id: function_run_id.clone(),
        idempotency_key: attempt_id.clone(),
        channel: EmailChannel::Email,
        recipient: DispatchRecipient { address: recipient },
        message: DispatchMessage {
            template_id,
            template_version,
            locale,
            subject,
            text,
            html,
            content_digest: message_digest,
        },
        context: DispatchContext {
            correlation_id: correlation_id.clone(),
        },
    };

    sqlx::query(
        r#"
        insert into notification.attempts (
            id, delivery_id, sequence, function_run_id, dispatch_event_id, status, started_at
        ) values ($1, $2, $3, $4, $5, 'dispatching', $6)
        "#,
    )
    .bind(&attempt_id)
    .bind(&delivery_id)
    .bind(sequence)
    .bind(&function_run_id)
    .bind(&dispatch_event_id)
    .bind(now)
    .execute(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    let updated = sqlx::query(
        r#"
        update notification.deliveries
        set status = 'attempting', revision = revision + 1, attempt_count = $2,
            next_attempt_at = null, updated_at = $3
        where id = $1 and revision = $4 and status in ('queued', 'retry_scheduled')
        "#,
    )
    .bind(&delivery_id)
    .bind(sequence)
    .bind(now)
    .bind(revision)
    .execute(&mut **tx.sql())
    .await
    .map_err(map_sql_error)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Notification delivery changed while it was being claimed",
        ));
    }
    tx.publish_outbox(&OutboxEvent {
        id: dispatch_event_id,
        event_name: EMAIL_DISPATCH_REQUESTED_EVENT.to_owned(),
        event_version: 1,
        source_module: "lenso/notification".to_owned(),
        aggregate_type: "notification.delivery".to_owned(),
        aggregate_id: delivery_id.clone(),
        correlation_id,
        causation_id,
        occurred_at: now,
        payload: serde_json::to_value(payload).map_err(|error| {
            AppError::new(
                ErrorCode::Internal,
                "Email dispatch payload encoding failed",
            )
            .with_source(error)
        })?,
        headers: json!({
            "schema_ref": "contracts/events/lenso.email.dispatch-requested.v1.schema.json",
            "contains_protected_delivery_content": true,
            "log_payload": false,
        }),
    })
    .await?;
    tx.commit().await?;
    Ok(Some(DispatchClaim {
        delivery_id,
        attempt_id,
        function_run_id,
    }))
}

fn stable_id(prefix: &str, input: &str) -> String {
    let digest = hex::encode(Sha256::digest(input.as_bytes()));
    format!("{prefix}_{}", &digest[..32])
}

fn map_sql_error(error: sqlx::Error) -> AppError {
    AppError::new(ErrorCode::Internal, "Notification dispatch storage failed").with_source(error)
}
