use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

use crate::domain::MAX_SAFE_WIRE_INTEGER;

use crate::error::{ErrorCode, NotificationError, NotificationResult};

pub(crate) const ADMIN_ATTEMPT_LIMIT: usize = 10;
pub(crate) const ADMIN_RECEIPT_LIMIT: usize = 1_000;
pub(crate) const ADMIN_RETRY_REQUEST_LIMIT: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliverySummary {
    pub id: String,
    pub recipient_mask: String,
    pub template_id: String,
    pub template_version: String,
    pub locale: String,
    pub status: String,
    pub revision: i64,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub redacted_preview: String,
    pub content_digest: String,
    pub correlation_id: String,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub final_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttemptRecord {
    pub id: String,
    pub sequence: i32,
    pub function_run_id: String,
    pub status: String,
    pub provider: Option<String>,
    pub remote_receipt_id: Option<String>,
    pub failure_code: Option<String>,
    pub failure_classification: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReceiptRecord {
    pub id: String,
    pub attempt_id: String,
    pub kind: String,
    pub source: String,
    pub remote_id: String,
    pub digest: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetryRecord {
    pub id: String,
    pub kind: String,
    pub requested_by: Option<String>,
    pub source_revision: i64,
    pub decision: String,
    pub reason: Option<String>,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliveryDetail {
    #[serde(flatten)]
    pub delivery: DeliverySummary,
    pub attempts: Vec<AttemptRecord>,
    pub receipts: Vec<ReceiptRecord>,
    pub retry_requests: Vec<RetryRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryResult {
    pub delivery_id: String,
    pub revision: i64,
    pub status: String,
    pub scheduled_at: DateTime<Utc>,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone)]
pub struct PostgresNotificationRepository {
    db: PgPool,
}

impl PostgresNotificationRepository {
    pub fn from_pool(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn list_deliveries(
        &self,
        limit: i64,
        cursor: Option<&str>,
        status: Option<&str>,
    ) -> NotificationResult<Vec<DeliverySummary>> {
        let rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                String,
                i64,
                i32,
                i32,
                String,
                String,
                String,
                Option<DateTime<Utc>>,
                Option<String>,
                DateTime<Utc>,
                DateTime<Utc>,
            ),
        >(
            r#"
            select deliveries.id, intents.recipient_mask, templates.template_id,
                   templates.version, intents.locale, deliveries.status, deliveries.revision,
                   deliveries.attempt_count, deliveries.max_attempts, snapshots.redacted_preview,
                   snapshots.content_digest, intents.correlation_id, deliveries.next_attempt_at,
                   deliveries.final_reason, deliveries.created_at, deliveries.updated_at
            from notification.deliveries deliveries
            join notification.intents intents on intents.id = deliveries.intent_id
            join notification.render_snapshots snapshots on snapshots.id = intents.snapshot_id
            join notification.template_releases templates on templates.id = snapshots.template_release_id
            where ($1::text is null or deliveries.status = $1)
              and ($2::text is null or deliveries.id < $2)
            order by deliveries.id desc
            limit $3
            "#,
        )
        .bind(status)
        .bind(cursor)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(map_sql_error)?;
        Ok(rows.into_iter().map(summary_from_row).collect())
    }

    pub async fn get_delivery(
        &self,
        delivery_id: &str,
    ) -> NotificationResult<Option<DeliveryDetail>> {
        let row = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                String,
                i64,
                i32,
                i32,
                String,
                String,
                String,
                Option<DateTime<Utc>>,
                Option<String>,
                DateTime<Utc>,
                DateTime<Utc>,
            ),
        >(
            r#"
            select deliveries.id, intents.recipient_mask, templates.template_id,
                   templates.version, intents.locale, deliveries.status, deliveries.revision,
                   deliveries.attempt_count, deliveries.max_attempts, snapshots.redacted_preview,
                   snapshots.content_digest, intents.correlation_id, deliveries.next_attempt_at,
                   deliveries.final_reason, deliveries.created_at, deliveries.updated_at
            from notification.deliveries deliveries
            join notification.intents intents on intents.id = deliveries.intent_id
            join notification.render_snapshots snapshots on snapshots.id = intents.snapshot_id
            join notification.template_releases templates on templates.id = snapshots.template_release_id
            where deliveries.id = $1
            "#,
        )
        .bind(delivery_id)
        .fetch_optional(&self.db)
        .await
        .map_err(map_sql_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let attempts = sqlx::query_as::<
            _,
            (
                String,
                i32,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                DateTime<Utc>,
                Option<DateTime<Utc>>,
            ),
        >(
            r#"
            select id, sequence, function_run_id, status, provider, remote_receipt_id,
                   failure_code, failure_classification, started_at, completed_at
            from notification.attempts
            where delivery_id = $1
            order by sequence asc
            limit $2
            "#,
        )
        .bind(delivery_id)
        .bind(i64::try_from(ADMIN_ATTEMPT_LIMIT + 1).expect("Admin attempt limit fits bigint"))
        .fetch_all(&self.db)
        .await
        .map_err(map_sql_error)?;
        if attempts.len() > ADMIN_ATTEMPT_LIMIT {
            return Err(admin_evidence_overflow());
        }
        let attempts = attempts
            .into_iter()
            .map(|row| AttemptRecord {
                id: row.0,
                sequence: row.1,
                function_run_id: row.2,
                status: row.3,
                provider: row.4,
                remote_receipt_id: row.5,
                failure_code: row.6,
                failure_classification: row.7,
                started_at: row.8,
                completed_at: row.9,
            })
            .collect();
        let receipts = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                String,
                DateTime<Utc>,
            ),
        >(
            r#"
            select id, attempt_id, kind, source, remote_id, digest, observed_at
            from notification.receipts
            where delivery_id = $1
            order by observed_at asc, id asc
            limit $2
            "#,
        )
        .bind(delivery_id)
        .bind(i64::try_from(ADMIN_RECEIPT_LIMIT + 1).expect("Admin receipt limit fits bigint"))
        .fetch_all(&self.db)
        .await
        .map_err(map_sql_error)?;
        if receipts.len() > ADMIN_RECEIPT_LIMIT {
            return Err(admin_evidence_overflow());
        }
        let receipts = receipts
            .into_iter()
            .map(|row| ReceiptRecord {
                id: row.0,
                attempt_id: row.1,
                kind: row.2,
                source: row.3,
                remote_id: row.4,
                digest: row.5,
                observed_at: row.6,
            })
            .collect();
        let retry_requests = sqlx::query_as::<
            _,
            (
                String,
                String,
                Option<String>,
                i64,
                String,
                Option<String>,
                Option<DateTime<Utc>>,
                DateTime<Utc>,
            ),
        >(
            r#"
            select id, kind, requested_by, source_revision, decision, reason, scheduled_at, created_at
            from notification.retry_requests
            where delivery_id = $1
            order by created_at asc, id asc
            limit $2
            "#,
        )
        .bind(delivery_id)
        .bind(
            i64::try_from(ADMIN_RETRY_REQUEST_LIMIT + 1)
                .expect("Admin retry-request limit fits bigint"),
        )
        .fetch_all(&self.db)
        .await
        .map_err(map_sql_error)?;
        if retry_requests.len() > ADMIN_RETRY_REQUEST_LIMIT {
            return Err(admin_evidence_overflow());
        }
        let retry_requests = retry_requests
            .into_iter()
            .map(|row| RetryRecord {
                id: row.0,
                kind: row.1,
                requested_by: row.2,
                source_revision: row.3,
                decision: row.4,
                reason: row.5,
                scheduled_at: row.6,
                created_at: row.7,
            })
            .collect();
        Ok(Some(DeliveryDetail {
            delivery: summary_from_row(row),
            attempts,
            receipts,
            retry_requests,
        }))
    }

    /// Manual retry is intentionally a "retry now" decision for an already
    /// retryable scheduled delivery. Permanent, exhausted, in-progress,
    /// delivered, and ambiguous deliveries fail closed.
    pub async fn request_manual_retry(
        &self,
        delivery_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        requested_by: &str,
        now: DateTime<Utc>,
    ) -> NotificationResult<RetryResult> {
        let mut tx = self.db.begin().await?;
        sqlx::query("select pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "notification:manual-retry:{delivery_id}:{idempotency_key}"
            ))
            .execute(tx.as_mut())
            .await
            .map_err(map_sql_error)?;
        if let Some(row) = sqlx::query_as::<_, (i64, String, Option<DateTime<Utc>>)>(
            r#"
            select deliveries.revision, deliveries.status, retry_requests.scheduled_at
            from notification.retry_requests retry_requests
            join notification.deliveries deliveries on deliveries.id = retry_requests.delivery_id
            where retry_requests.delivery_id = $1 and retry_requests.idempotency_key = $2
            "#,
        )
        .bind(delivery_id)
        .bind(idempotency_key)
        .fetch_optional(tx.as_mut())
        .await
        .map_err(map_sql_error)?
        {
            let scheduled_at = row.2.ok_or_else(|| {
                NotificationError::new(
                    ErrorCode::Conflict,
                    "Existing manual retry request was rejected",
                )
            })?;
            tx.commit().await?;
            return Ok(RetryResult {
                delivery_id: delivery_id.to_owned(),
                revision: row.0,
                status: row.1,
                scheduled_at,
                idempotent_replay: true,
            });
        }
        let delivery = sqlx::query_as::<_, (String, i64, i32, i32)>(
            r#"
            select status, revision, attempt_count, max_attempts
            from notification.deliveries
            where id = $1
            for update
            "#,
        )
        .bind(delivery_id)
        .fetch_optional(tx.as_mut())
        .await
        .map_err(map_sql_error)?
        .ok_or_else(|| {
            NotificationError::new(ErrorCode::NotFound, "Notification delivery was not found")
        })?;
        if delivery.1 != expected_revision {
            return Err(NotificationError::new(
                ErrorCode::Conflict,
                "Notification delivery revision is stale",
            ));
        }
        if delivery.1 >= MAX_SAFE_WIRE_INTEGER {
            return Err(NotificationError::new(
                ErrorCode::Conflict,
                "Notification delivery revision exhausted the portable wire range",
            ));
        }
        if delivery.0 != "retry_scheduled" || delivery.2 >= delivery.3 {
            return Err(NotificationError::new(
                ErrorCode::Conflict,
                "Notification delivery is not eligible for retry",
            ));
        }
        let retry_id = stable_id(
            "ntf_rty",
            &format!("manual:{delivery_id}:{idempotency_key}"),
        );
        sqlx::query(
            r#"
            insert into notification.retry_requests (
                id, delivery_id, kind, requested_by, source_revision, idempotency_key,
                decision, reason, scheduled_at, created_at
            ) values ($1, $2, 'manual', $3, $4, $5, 'scheduled', 'operator_retry_now', $6, $6)
            "#,
        )
        .bind(retry_id)
        .bind(delivery_id)
        .bind(requested_by)
        .bind(expected_revision)
        .bind(idempotency_key)
        .bind(now)
        .execute(tx.as_mut())
        .await
        .map_err(map_sql_error)?;
        let new_revision = expected_revision + 1;
        let result = sqlx::query(
            r#"
            update notification.deliveries
            set next_attempt_at = $3, revision = $4, updated_at = $3
            where id = $1 and revision = $2 and revision < $5
              and status = 'retry_scheduled'
            "#,
        )
        .bind(delivery_id)
        .bind(expected_revision)
        .bind(now)
        .bind(new_revision)
        .bind(MAX_SAFE_WIRE_INTEGER)
        .execute(tx.as_mut())
        .await
        .map_err(map_sql_error)?;
        if result.rows_affected() != 1 {
            return Err(NotificationError::new(
                ErrorCode::Conflict,
                "Notification delivery changed while retry was scheduled",
            ));
        }
        tx.commit().await?;
        Ok(RetryResult {
            delivery_id: delivery_id.to_owned(),
            revision: new_revision,
            status: "retry_scheduled".to_owned(),
            scheduled_at: now,
            idempotent_replay: false,
        })
    }
}

fn admin_evidence_overflow() -> NotificationError {
    NotificationError::new(
        ErrorCode::EvidenceOverflow,
        "Notification delivery evidence exceeds the bounded Admin projection",
    )
}

#[allow(clippy::type_complexity)]
fn summary_from_row(
    row: (
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        i32,
        i32,
        String,
        String,
        String,
        Option<DateTime<Utc>>,
        Option<String>,
        DateTime<Utc>,
        DateTime<Utc>,
    ),
) -> DeliverySummary {
    DeliverySummary {
        id: row.0,
        recipient_mask: row.1,
        template_id: row.2,
        template_version: row.3,
        locale: row.4,
        status: row.5,
        revision: row.6,
        attempt_count: row.7,
        max_attempts: row.8,
        redacted_preview: row.9,
        content_digest: row.10,
        correlation_id: row.11,
        next_attempt_at: row.12,
        final_reason: row.13,
        created_at: row.14,
        updated_at: row.15,
    }
}

fn stable_id(prefix: &str, input: &str) -> String {
    let digest = hex::encode(Sha256::digest(input.as_bytes()));
    format!("{prefix}_{}", &digest[..32])
}

fn map_sql_error(error: sqlx::Error) -> NotificationError {
    NotificationError::new(
        ErrorCode::Internal,
        "Notification Business API storage operation failed",
    )
    .with_source(error)
}
