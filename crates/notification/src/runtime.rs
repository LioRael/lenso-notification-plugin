use crate::domain::MAX_SAFE_WIRE_INTEGER;
use crate::error::{ErrorCode, NotificationError, NotificationResult};
use crate::snapshot::{ProtectedValue, SnapshotProtector};
use lenso_capability_email_dispatch::{
    DispatchRequest, DispatchRequestMessage, DispatchRequestRecipient,
};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct DispatchClaim {
    pub delivery_id: String,
    pub attempt_id: String,
    pub run_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DispatchWork {
    pub claim: DispatchClaim,
    pub request: DispatchRequest,
}

#[allow(clippy::too_many_arguments)]
type DueRow = (
    String,
    i64,
    i32,
    i32,
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
    String,
);

/// Claims one due delivery and appends its immutable attempt before returning
/// sensitive dispatch work to the exact bound Email Dispatch provider.
pub async fn claim_one_due(
    db: &PgPool,
    protector: &dyn SnapshotProtector,
    now: chrono::DateTime<chrono::Utc>,
) -> NotificationResult<Option<DispatchWork>> {
    let mut tx = db.begin().await?;
    let row = sqlx::query_as::<_, DueRow>(
        r#"
        select deliveries.id, deliveries.revision, deliveries.attempt_count, deliveries.max_attempts,
               intents.correlation_id, intents.recipient_ciphertext,
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
    .fetch_optional(tx.as_mut())
    .await
    .map_err(map_sql_error)?;
    let Some((
        delivery_id,
        revision,
        attempt_count,
        max_attempts,
        correlation_id,
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
    if revision >= MAX_SAFE_WIRE_INTEGER {
        return Err(NotificationError::new(
            ErrorCode::Conflict,
            "Notification delivery revision exhausted the portable wire range",
        ));
    }
    let sequence = attempt_count + 1;
    if sequence > max_attempts {
        return Err(NotificationError::new(
            ErrorCode::Conflict,
            "Notification delivery exhausted before dispatch",
        ));
    }
    let attempt_id = stable_id("ntf_att", &format!("{delivery_id}:{sequence}"));
    let run_id = stable_id("ntf_run", &attempt_id);
    let dispatch_record_id = stable_id("dispatch", &attempt_id);

    let reveal = |ciphertext: String, key_reference: String| {
        protector.reveal(&ProtectedValue {
            ciphertext,
            key_reference,
        })
    };
    let request = DispatchRequest {
        delivery_id: delivery_id.clone(),
        attempt_id: attempt_id.clone(),
        run_id: run_id.clone(),
        idempotency_key: attempt_id.clone(),
        recipient: DispatchRequestRecipient {
            address: reveal(recipient_ciphertext, recipient_key_ref)?,
        },
        message: DispatchRequestMessage {
            template_id,
            template_version,
            locale,
            subject: reveal(subject_ciphertext, protection_key_ref.clone())?,
            text: reveal(text_ciphertext, protection_key_ref.clone())?,
            html: reveal(html_ciphertext, protection_key_ref)?,
            content_digest: message_digest,
        },
        correlation_id,
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
    .bind(&run_id)
    .bind(dispatch_record_id)
    .bind(now)
    .execute(tx.as_mut())
    .await
    .map_err(map_sql_error)?;
    let updated = sqlx::query(
        r#"
        update notification.deliveries
        set status = 'attempting', revision = revision + 1, attempt_count = $2,
            next_attempt_at = null, updated_at = $3
        where id = $1 and revision = $4 and revision < $5
          and status in ('queued', 'retry_scheduled')
        "#,
    )
    .bind(&delivery_id)
    .bind(sequence)
    .bind(now)
    .bind(revision)
    .bind(MAX_SAFE_WIRE_INTEGER)
    .execute(tx.as_mut())
    .await
    .map_err(map_sql_error)?;
    if updated.rows_affected() != 1 {
        return Err(NotificationError::new(
            ErrorCode::Conflict,
            "Notification delivery changed while it was being claimed",
        ));
    }
    tx.commit().await?;
    Ok(Some(DispatchWork {
        claim: DispatchClaim {
            delivery_id,
            attempt_id,
            run_id,
        },
        request,
    }))
}

fn stable_id(prefix: &str, input: &str) -> String {
    let digest = hex::encode(Sha256::digest(input.as_bytes()));
    format!("{prefix}_{}", &digest[..32])
}

fn map_sql_error(error: sqlx::Error) -> NotificationError {
    NotificationError::new(ErrorCode::Internal, "Notification dispatch storage failed")
        .with_source(error)
}
