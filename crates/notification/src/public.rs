//! Private intent storage used behind the generated Transactional Capability.

use crate::domain::DeliveryStatus;
use crate::error::{ErrorCode, NotificationError, NotificationResult};
use crate::snapshot::{
    SnapshotProtector, content_digest, mask_email, redact_preview, request_digest,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Transaction};

pub const ORGANIZATION_INVITATION_TEMPLATE_ID: &str = "organization-invitation";
pub const ORGANIZATION_INVITATION_TEMPLATE_VERSION: &str = "v1";
pub const ACCESS_REQUEST_TEMPLATE_VERSION: &str = "v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSource {
    pub module_id: String,
    pub entity_type: String,
    pub entity_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailRecipient {
    pub address: String,
    pub display_name: Option<String>,
    pub locale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationInvitationTemplateV1 {
    pub organization_id: String,
    pub organization_name: String,
    pub invitation_id: String,
    pub invitation_url: String,
    pub inviter_display_name: Option<String>,
    pub role_name: Option<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateTransactionalEmailIntent {
    pub source: IntentSource,
    pub recipient: EmailRecipient,
    pub template: OrganizationInvitationTemplateV1,
    pub idempotency_key: String,
    pub correlation_id: String,
    pub causation_id: Option<String>,
    pub requested_by: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessRequestNotificationEvent {
    Submitted,
    Approved,
    Denied,
    Expiring,
}

impl AccessRequestNotificationEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expiring => "expiring",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRequestRoleV1 {
    pub role_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRequestScopeV1 {
    pub kind: String,
    pub id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRequestNotificationTemplateV1 {
    pub request_id: String,
    pub organization_id: String,
    pub event: AccessRequestNotificationEvent,
    pub role: AccessRequestRoleV1,
    pub scope: AccessRequestScopeV1,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAccessRequestNotificationIntent {
    pub source: IntentSource,
    pub recipient: EmailRecipient,
    pub template: AccessRequestNotificationTemplateV1,
    pub idempotency_key: String,
    pub correlation_id: String,
    pub causation_id: Option<String>,
    pub requested_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionalIntentReceipt {
    pub intent_id: String,
    pub delivery_id: String,
    pub status: DeliveryStatus,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RenderedTemplate {
    pub template_id: String,
    pub template_version: String,
    pub requested_locale: String,
    pub resolved_locale: String,
    pub fallback_used: bool,
    pub renderer_identity: String,
    pub template_digest: String,
    pub content_digest: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

struct IntentPersistence<'a> {
    source: &'a IntentSource,
    recipient: &'a EmailRecipient,
    idempotency_key: &'a str,
    correlation_id: &'a str,
    causation_id: Option<&'a str>,
    requested_by: Option<&'a str>,
    purpose: &'static str,
    template_id: &'a str,
    template_version: &'a str,
    template_locale: &'a str,
    renderer_identity: &'a str,
    template_digest: &'a str,
    content_digest: &'a str,
    request_digest: String,
    rendered: &'a RenderedTemplate,
}

/// Returns an already committed replay without consulting the Template Provider.
///
/// The final transactional write still performs the same advisory-lock check, so
/// this read-only fast path cannot weaken concurrent idempotency guarantees.
pub(crate) async fn find_transactional_email_intent_replay(
    pool: &PgPool,
    request: &CreateTransactionalEmailIntent,
    now: DateTime<Utc>,
) -> NotificationResult<Option<TransactionalIntentReceipt>> {
    validate_invitation_request(request, now)?;
    find_idempotent_intent_in_pool(
        pool,
        &request.source.module_id,
        &request.idempotency_key,
        &request_digest(request)?,
    )
    .await
}

/// Returns an already committed access-request replay without rendering again.
pub(crate) async fn find_access_request_notification_replay(
    pool: &PgPool,
    request: &CreateAccessRequestNotificationIntent,
    now: DateTime<Utc>,
) -> NotificationResult<Option<TransactionalIntentReceipt>> {
    validate_access_request(request, now)?;
    find_idempotent_intent_in_pool(
        pool,
        &request.source.module_id,
        &request.idempotency_key,
        &request_digest(request)?,
    )
    .await
}

/// Persists one idempotent intent inside a Notification-owned transaction.
pub(crate) async fn create_transactional_email_intent_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    request: &CreateTransactionalEmailIntent,
    rendered: &RenderedTemplate,
    now: DateTime<Utc>,
    protector: &dyn SnapshotProtector,
) -> NotificationResult<TransactionalIntentReceipt> {
    validate_invitation_request(request, now)?;
    validate_rendered_template(
        rendered,
        ORGANIZATION_INVITATION_TEMPLATE_ID,
        ORGANIZATION_INVITATION_TEMPLATE_VERSION,
        &request.recipient.locale,
    )?;
    let digest = request_digest(request)?;
    persist_intent(
        tx,
        IntentPersistence {
            source: &request.source,
            recipient: &request.recipient,
            idempotency_key: &request.idempotency_key,
            correlation_id: &request.correlation_id,
            causation_id: request.causation_id.as_deref(),
            requested_by: request.requested_by.as_deref(),
            purpose: "transactional.organization_invitation",
            template_id: &rendered.template_id,
            template_version: &rendered.template_version,
            template_locale: &rendered.resolved_locale,
            renderer_identity: &rendered.renderer_identity,
            template_digest: &rendered.template_digest,
            content_digest: &rendered.content_digest,
            request_digest: digest,
            rendered,
        },
        now,
        protector,
    )
    .await
}

/// Persists one bounded access-request lifecycle intent in Notification state.
pub(crate) async fn create_access_request_notification_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    request: &CreateAccessRequestNotificationIntent,
    rendered: &RenderedTemplate,
    now: DateTime<Utc>,
    protector: &dyn SnapshotProtector,
) -> NotificationResult<TransactionalIntentReceipt> {
    validate_access_request(request, now)?;
    let template_id = access_request_template_id(request.template.event);
    validate_rendered_template(
        rendered,
        template_id,
        ACCESS_REQUEST_TEMPLATE_VERSION,
        &request.recipient.locale,
    )?;
    let digest = request_digest(request)?;
    persist_intent(
        tx,
        IntentPersistence {
            source: &request.source,
            recipient: &request.recipient,
            idempotency_key: &request.idempotency_key,
            correlation_id: &request.correlation_id,
            causation_id: request.causation_id.as_deref(),
            requested_by: request.requested_by.as_deref(),
            purpose: "transactional.access_request",
            template_id: &rendered.template_id,
            template_version: &rendered.template_version,
            template_locale: &rendered.resolved_locale,
            renderer_identity: &rendered.renderer_identity,
            template_digest: &rendered.template_digest,
            content_digest: &rendered.content_digest,
            request_digest: digest,
            rendered,
        },
        now,
        protector,
    )
    .await
}

async fn persist_intent(
    tx: &mut Transaction<'_, Postgres>,
    intent: IntentPersistence<'_>,
    now: DateTime<Utc>,
    protector: &dyn SnapshotProtector,
) -> NotificationResult<TransactionalIntentReceipt> {
    // Serialize contenders before checking the business idempotency record so
    // same-key requests cannot race into two snapshots.
    sqlx::query("select pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "notification:{}:{}",
            intent.source.module_id, intent.idempotency_key
        ))
        .execute(tx.as_mut())
        .await
        .map_err(map_sql_error)?;

    if let Some(existing) = find_idempotent_intent(
        tx,
        &intent.source.module_id,
        intent.idempotency_key,
        &intent.request_digest,
    )
    .await?
    {
        return Ok(existing);
    }

    let message_digest = content_digest(
        &intent.rendered.subject,
        &intent.rendered.text,
        &intent.rendered.html,
    );
    if message_digest != intent.content_digest {
        return Err(NotificationError::new(
            ErrorCode::Internal,
            "Notification Template content digest does not match rendered content",
        ));
    }
    let template_release_id = stable_id(
        "ntf_tpl",
        &format!(
            "{}:{}:{}",
            intent.template_id, intent.template_version, intent.template_locale
        ),
    );
    sqlx::query(
        r#"
        insert into notification.template_releases (
            id, template_id, version, locale, renderer_identity, template_digest, created_at
        ) values ($1, $2, $3, $4, $5, $6, $7)
        on conflict (template_id, version, locale) do nothing
        "#,
    )
    .bind(&template_release_id)
    .bind(intent.template_id)
    .bind(intent.template_version)
    .bind(intent.template_locale)
    .bind(intent.renderer_identity)
    .bind(intent.template_digest)
    .bind(now)
    .execute(tx.as_mut())
    .await
    .map_err(map_sql_error)?;
    let stored_template_digest = sqlx::query_scalar::<_, String>(
        r#"
        select template_digest
        from notification.template_releases
        where template_id = $1 and version = $2 and locale = $3
        "#,
    )
    .bind(intent.template_id)
    .bind(intent.template_version)
    .bind(intent.template_locale)
    .fetch_one(tx.as_mut())
    .await
    .map_err(map_sql_error)?;
    if stored_template_digest != intent.template_digest {
        return Err(NotificationError::new(
            ErrorCode::Internal,
            "Notification template release is immutable",
        ));
    }

    let subject = protector.protect(&intent.rendered.subject)?;
    let text = protector.protect(&intent.rendered.text)?;
    let html = protector.protect(&intent.rendered.html)?;
    if subject.key_reference != text.key_reference || text.key_reference != html.key_reference {
        return Err(NotificationError::new(
            ErrorCode::Internal,
            "Notification snapshot protection key changed during rendering",
        ));
    }
    let recipient = protector.protect(&intent.recipient.address)?;
    let snapshot_id = stable_id("ntf_snp", &intent.request_digest);
    let intent_id = stable_id(
        "ntf_int",
        &format!(
            "{}:{}:{}",
            intent.source.module_id, intent.idempotency_key, intent.request_digest
        ),
    );
    let delivery_id = stable_id("ntf_dlv", &intent_id);

    sqlx::query(
        r#"
        insert into notification.render_snapshots (
            id, template_release_id, subject_ciphertext, text_ciphertext, html_ciphertext,
            protection_key_ref, content_digest, redacted_preview, created_at
        ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(&snapshot_id)
    .bind(&template_release_id)
    .bind(&subject.ciphertext)
    .bind(&text.ciphertext)
    .bind(&html.ciphertext)
    .bind(&subject.key_reference)
    .bind(&message_digest)
    .bind(redact_preview(&intent.rendered.text))
    .bind(now)
    .execute(tx.as_mut())
    .await
    .map_err(map_sql_error)?;

    sqlx::query(
        r#"
        insert into notification.intents (
            id, purpose, source_module, source_entity_type, source_entity_id,
            recipient_ciphertext, recipient_key_ref, recipient_mask, locale, snapshot_id,
            idempotency_key, request_digest, requested_by, correlation_id, causation_id,
            requested_at
        ) values (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
        )
        "#,
    )
    .bind(&intent_id)
    .bind(intent.purpose)
    .bind(&intent.source.module_id)
    .bind(&intent.source.entity_type)
    .bind(&intent.source.entity_id)
    .bind(&recipient.ciphertext)
    .bind(&recipient.key_reference)
    .bind(mask_email(&intent.recipient.address))
    .bind(&intent.recipient.locale)
    .bind(&snapshot_id)
    .bind(intent.idempotency_key)
    .bind(&intent.request_digest)
    .bind(intent.requested_by)
    .bind(intent.correlation_id)
    .bind(intent.causation_id)
    .bind(now)
    .execute(tx.as_mut())
    .await
    .map_err(map_sql_error)?;

    sqlx::query(
        r#"
        insert into notification.deliveries (
            id, intent_id, channel, status, revision, attempt_count, max_attempts,
            next_attempt_at, created_at, updated_at
        ) values ($1, $2, 'email', 'queued', 1, 0, 4, $3, $3, $3)
        "#,
    )
    .bind(&delivery_id)
    .bind(&intent_id)
    .bind(now)
    .execute(tx.as_mut())
    .await
    .map_err(map_sql_error)?;

    Ok(TransactionalIntentReceipt {
        intent_id,
        delivery_id,
        status: DeliveryStatus::Queued,
        idempotent_replay: false,
    })
}

async fn find_idempotent_intent(
    tx: &mut Transaction<'_, Postgres>,
    source_module: &str,
    idempotency_key: &str,
    digest: &str,
) -> NotificationResult<Option<TransactionalIntentReceipt>> {
    let existing = sqlx::query_as::<_, (String, String, String, String, i64)>(
        r#"
        select intents.id, deliveries.id, intents.request_digest, deliveries.status, deliveries.revision
        from notification.intents intents
        join notification.deliveries deliveries on deliveries.intent_id = intents.id
        where intents.source_module = $1 and intents.idempotency_key = $2
        "#,
    )
    .bind(source_module)
    .bind(idempotency_key)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(map_sql_error)?;
    project_idempotent_intent(existing, digest)
}

async fn find_idempotent_intent_in_pool(
    pool: &PgPool,
    source_module: &str,
    idempotency_key: &str,
    digest: &str,
) -> NotificationResult<Option<TransactionalIntentReceipt>> {
    let existing = sqlx::query_as::<_, (String, String, String, String, i64)>(
        r#"
        select intents.id, deliveries.id, intents.request_digest, deliveries.status, deliveries.revision
        from notification.intents intents
        join notification.deliveries deliveries on deliveries.intent_id = intents.id
        where intents.source_module = $1 and intents.idempotency_key = $2
        "#,
    )
    .bind(source_module)
    .bind(idempotency_key)
    .fetch_optional(pool)
    .await
    .map_err(map_sql_error)?;
    project_idempotent_intent(existing, digest)
}

fn project_idempotent_intent(
    existing: Option<(String, String, String, String, i64)>,
    digest: &str,
) -> NotificationResult<Option<TransactionalIntentReceipt>> {
    let Some((intent_id, delivery_id, stored_digest, status, _revision)) = existing else {
        return Ok(None);
    };
    if stored_digest != digest {
        return Err(NotificationError::new(
            ErrorCode::Conflict,
            "Notification idempotency key was used with different input",
        ));
    }
    let status = status.parse().map_err(|_| {
        NotificationError::new(
            ErrorCode::Internal,
            "Notification delivery has an invalid stored status",
        )
    })?;
    Ok(Some(TransactionalIntentReceipt {
        intent_id,
        delivery_id,
        status,
        idempotent_replay: true,
    }))
}

fn validate_invitation_request(
    request: &CreateTransactionalEmailIntent,
    now: DateTime<Utc>,
) -> NotificationResult<()> {
    for (field, value, minimum, maximum) in [
        (
            "source.module_id",
            request.source.module_id.as_str(),
            1,
            160,
        ),
        (
            "source.entity_type",
            request.source.entity_type.as_str(),
            1,
            160,
        ),
        (
            "source.entity_id",
            request.source.entity_id.as_str(),
            1,
            240,
        ),
        (
            "recipient.address",
            request.recipient.address.as_str(),
            3,
            320,
        ),
        ("recipient.locale", request.recipient.locale.as_str(), 2, 32),
        ("idempotency_key", request.idempotency_key.as_str(), 1, 240),
        ("correlation_id", request.correlation_id.as_str(), 1, 240),
        (
            "template.organization_id",
            request.template.organization_id.as_str(),
            1,
            240,
        ),
        (
            "template.organization_name",
            request.template.organization_name.as_str(),
            1,
            240,
        ),
        (
            "template.invitation_id",
            request.template.invitation_id.as_str(),
            1,
            240,
        ),
        (
            "template.invitation_url",
            request.template.invitation_url.as_str(),
            1,
            4_096,
        ),
    ] {
        let length = value.chars().count();
        if value.trim().is_empty() || !(minimum..=maximum).contains(&length) {
            return Err(NotificationError::new(
                ErrorCode::Validation,
                format!("{field} must contain between {minimum} and {maximum} characters"),
            ));
        }
    }
    for (field, value, maximum) in [
        (
            "recipient.display_name",
            request.recipient.display_name.as_deref(),
            240,
        ),
        (
            "template.inviter_display_name",
            request.template.inviter_display_name.as_deref(),
            240,
        ),
        (
            "template.role_name",
            request.template.role_name.as_deref(),
            160,
        ),
        ("causation_id", request.causation_id.as_deref(), 240),
        ("requested_by", request.requested_by.as_deref(), 240),
    ] {
        if value.is_some_and(|value| value.chars().count() > maximum) {
            return Err(NotificationError::new(
                ErrorCode::Validation,
                format!("{field} must contain at most {maximum} characters"),
            ));
        }
    }
    if !request.recipient.address.contains('@') {
        return Err(NotificationError::new(
            ErrorCode::Validation,
            "recipient.address must be an email address",
        ));
    }
    if !matches!(request.recipient.locale.as_str(), "en" | "en-US") {
        return Err(NotificationError::new(
            ErrorCode::Validation,
            "organization-invitation@v1 supports locale en or en-US",
        ));
    }
    if !(request.template.invitation_url.starts_with("https://")
        || request
            .template
            .invitation_url
            .starts_with("http://localhost"))
    {
        return Err(NotificationError::new(
            ErrorCode::Validation,
            "template.invitation_url must use HTTPS",
        ));
    }
    if request.template.expires_at <= now {
        return Err(NotificationError::new(
            ErrorCode::Validation,
            "template.expires_at must be in the future",
        ));
    }
    if request.source.entity_type != "organization_invitation"
        || request.source.entity_id != request.template.invitation_id
    {
        return Err(NotificationError::new(
            ErrorCode::Validation,
            "Notification source must identify the rendered organization invitation",
        ));
    }
    Ok(())
}

fn validate_access_request(
    request: &CreateAccessRequestNotificationIntent,
    now: DateTime<Utc>,
) -> NotificationResult<()> {
    for (field, value, minimum, maximum) in [
        (
            "source.module_id",
            request.source.module_id.as_str(),
            1,
            160,
        ),
        (
            "source.entity_type",
            request.source.entity_type.as_str(),
            1,
            160,
        ),
        (
            "source.entity_id",
            request.source.entity_id.as_str(),
            1,
            240,
        ),
        (
            "recipient.address",
            request.recipient.address.as_str(),
            3,
            320,
        ),
        ("recipient.locale", request.recipient.locale.as_str(), 2, 32),
        (
            "template.request_id",
            request.template.request_id.as_str(),
            1,
            160,
        ),
        (
            "template.organization_id",
            request.template.organization_id.as_str(),
            1,
            240,
        ),
        (
            "template.role.role_id",
            request.template.role.role_id.as_str(),
            1,
            160,
        ),
        (
            "template.scope.kind",
            request.template.scope.kind.as_str(),
            1,
            160,
        ),
        (
            "template.scope.id",
            request.template.scope.id.as_str(),
            1,
            240,
        ),
        ("idempotency_key", request.idempotency_key.as_str(), 1, 240),
        ("correlation_id", request.correlation_id.as_str(), 1, 240),
    ] {
        let length = value.chars().count();
        if value.trim().is_empty() || !(minimum..=maximum).contains(&length) {
            return Err(NotificationError::new(
                ErrorCode::Validation,
                format!("{field} must contain between {minimum} and {maximum} characters"),
            ));
        }
    }
    for (field, value, maximum) in [
        (
            "recipient.display_name",
            request.recipient.display_name.as_deref(),
            240,
        ),
        (
            "template.role.display_name",
            request.template.role.display_name.as_deref(),
            160,
        ),
        (
            "template.scope.display_name",
            request.template.scope.display_name.as_deref(),
            240,
        ),
        ("causation_id", request.causation_id.as_deref(), 240),
        ("requested_by", request.requested_by.as_deref(), 240),
    ] {
        if value.is_some_and(|value| value.chars().count() > maximum) {
            return Err(NotificationError::new(
                ErrorCode::Validation,
                format!("{field} must contain at most {maximum} characters"),
            ));
        }
    }
    if !request.recipient.address.contains('@') {
        return Err(NotificationError::new(
            ErrorCode::Validation,
            "recipient.address must be an email address",
        ));
    }
    if !matches!(request.recipient.locale.as_str(), "en" | "en-US") {
        return Err(NotificationError::new(
            ErrorCode::Validation,
            "access-request@v1 supports locale en or en-US",
        ));
    }
    if request.source.entity_type != "access_request"
        || request.source.entity_id != request.template.request_id
    {
        return Err(NotificationError::new(
            ErrorCode::Validation,
            "Notification source must identify the rendered access request",
        ));
    }
    let stable_idempotency_key = format!(
        "access-request:{}:{}",
        request.template.request_id,
        request.template.event.as_str()
    );
    if request.idempotency_key != stable_idempotency_key {
        return Err(NotificationError::new(
            ErrorCode::Validation,
            "access-request notification idempotency must be request-and-event stable",
        ));
    }
    match (request.template.event, request.template.expires_at) {
        (AccessRequestNotificationEvent::Expiring, Some(expires_at)) if expires_at > now => {}
        (AccessRequestNotificationEvent::Expiring, _) => {
            return Err(NotificationError::new(
                ErrorCode::Validation,
                "expiring access-request notifications require a future expiry",
            ));
        }
        (AccessRequestNotificationEvent::Denied, Some(_)) => {
            return Err(NotificationError::new(
                ErrorCode::Validation,
                "denied access-request notifications cannot claim an expiry",
            ));
        }
        (_, Some(expires_at)) if expires_at <= now => {
            return Err(NotificationError::new(
                ErrorCode::Validation,
                "access-request notification expiry must be in the future",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn validate_rendered_template(
    rendered: &RenderedTemplate,
    expected_template_id: &str,
    expected_version: &str,
    expected_requested_locale: &str,
) -> NotificationResult<()> {
    let metadata_valid = rendered.template_id == expected_template_id
        && rendered.template_version == expected_version
        && rendered.requested_locale == expected_requested_locale
        && rendered.fallback_used
            == (rendered.requested_locale.as_str() != rendered.resolved_locale.as_str())
        && bounded_non_blank(&rendered.resolved_locale, 2, 32)
        && bounded_non_blank(&rendered.renderer_identity, 1, 160)
        && valid_sha256_digest(&rendered.template_digest)
        && valid_sha256_digest(&rendered.content_digest);
    let content_valid = bounded_non_blank(&rendered.subject, 1, 998)
        && !rendered.subject.contains(['\r', '\n'])
        && bounded_non_blank(&rendered.text, 1, 131_072)
        && bounded_non_blank(&rendered.html, 1, 262_144)
        && content_digest(&rendered.subject, &rendered.text, &rendered.html)
            == rendered.content_digest;
    if !metadata_valid || !content_valid {
        return Err(NotificationError::new(
            ErrorCode::Internal,
            "Notification Template Provider returned an invalid render projection",
        ));
    }
    Ok(())
}

fn bounded_non_blank(value: &str, minimum: usize, maximum: usize) -> bool {
    let length = value.chars().count();
    !value.trim().is_empty() && (minimum..=maximum).contains(&length)
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(crate) fn access_request_template_id(event: AccessRequestNotificationEvent) -> &'static str {
    match event {
        AccessRequestNotificationEvent::Submitted => "access-request-submitted",
        AccessRequestNotificationEvent::Approved => "access-request-approved",
        AccessRequestNotificationEvent::Denied => "access-request-denied",
        AccessRequestNotificationEvent::Expiring => "access-request-expiring",
    }
}

fn stable_id(prefix: &str, input: &str) -> String {
    let digest = hex::encode(Sha256::digest(input.as_bytes()));
    format!("{prefix}_{}", &digest[..32])
}

fn map_sql_error(error: sqlx::Error) -> NotificationError {
    NotificationError::new(ErrorCode::Internal, "Notification storage operation failed")
        .with_source(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_template_projection_is_digest_bound_and_version_exact() {
        let mut rendered = rendered_template("organization-invitation", "en", "en");
        validate_rendered_template(&rendered, "organization-invitation", "v1", "en")
            .expect("valid render projection");

        rendered.template_version = "v2".to_owned();
        assert_eq!(
            validate_rendered_template(&rendered, "organization-invitation", "v1", "en")
                .expect_err("version mismatch")
                .code,
            ErrorCode::Internal
        );

        rendered.template_version = "v1".to_owned();
        rendered.content_digest = format!("sha256:{}", "0".repeat(64));
        assert_eq!(
            validate_rendered_template(&rendered, "organization-invitation", "v1", "en")
                .expect_err("content digest mismatch")
                .code,
            ErrorCode::Internal
        );
    }

    #[test]
    fn only_organization_invitation_is_accepted() {
        let now = Utc::now();
        let request = CreateTransactionalEmailIntent {
            source: IntentSource {
                module_id: "organization".to_owned(),
                entity_type: "arbitrary_campaign".to_owned(),
                entity_id: "inv_1".to_owned(),
            },
            recipient: EmailRecipient {
                address: "member@example.com".to_owned(),
                display_name: None,
                locale: "en".to_owned(),
            },
            template: OrganizationInvitationTemplateV1 {
                organization_id: "org_1".to_owned(),
                organization_name: "Acme".to_owned(),
                invitation_id: "inv_1".to_owned(),
                invitation_url: "https://example.test/invite/token".to_owned(),
                inviter_display_name: None,
                role_name: None,
                expires_at: now + chrono::Duration::hours(1),
            },
            idempotency_key: "organization-invitation:inv_1".to_owned(),
            correlation_id: "corr_1".to_owned(),
            causation_id: None,
            requested_by: None,
        };
        assert_eq!(
            validate_invitation_request(&request, now)
                .expect_err("campaign rejected")
                .code,
            ErrorCode::Validation
        );
    }

    #[test]
    fn rendered_template_fallback_metadata_must_be_self_consistent() {
        let mut rendered = rendered_template("access-request-submitted", "en-US", "en");
        rendered.fallback_used = true;
        validate_rendered_template(&rendered, "access-request-submitted", "v1", "en-US")
            .expect("valid fallback projection");

        rendered.fallback_used = false;
        assert_eq!(
            validate_rendered_template(&rendered, "access-request-submitted", "v1", "en-US")
                .expect_err("inconsistent fallback metadata")
                .code,
            ErrorCode::Internal
        );
    }

    #[test]
    fn access_request_requires_request_event_idempotency_and_bounded_expiry_semantics() {
        let now = Utc::now();
        let mut request = access_request_fixture(now);
        validate_access_request(&request, now).expect("submitted fixture");

        request.idempotency_key = "caller-chosen-key".to_owned();
        assert_eq!(
            validate_access_request(&request, now)
                .expect_err("unstable idempotency")
                .code,
            ErrorCode::Validation
        );

        let mut expiring = access_request_fixture(now);
        expiring.template.event = AccessRequestNotificationEvent::Expiring;
        expiring.template.expires_at = None;
        expiring.idempotency_key =
            format!("access-request:{}:expiring", expiring.template.request_id);
        assert_eq!(
            validate_access_request(&expiring, now)
                .expect_err("expiring requires expiry")
                .code,
            ErrorCode::Validation
        );

        let mut denied = access_request_fixture(now);
        denied.template.event = AccessRequestNotificationEvent::Denied;
        denied.idempotency_key = format!("access-request:{}:denied", denied.template.request_id);
        assert_eq!(
            validate_access_request(&denied, now)
                .expect_err("denied has no expiry claim")
                .code,
            ErrorCode::Validation
        );
    }

    fn access_request_fixture(now: DateTime<Utc>) -> CreateAccessRequestNotificationIntent {
        CreateAccessRequestNotificationIntent {
            source: IntentSource {
                module_id: "access-requests".to_owned(),
                entity_type: "access_request".to_owned(),
                entity_id: "ar_1".to_owned(),
            },
            recipient: EmailRecipient {
                address: "member@example.com".to_owned(),
                display_name: None,
                locale: "en".to_owned(),
            },
            template: AccessRequestNotificationTemplateV1 {
                request_id: "ar_1".to_owned(),
                organization_id: "org_1".to_owned(),
                event: AccessRequestNotificationEvent::Submitted,
                role: AccessRequestRoleV1 {
                    role_id: "role_member".to_owned(),
                    display_name: Some("Member".to_owned()),
                },
                scope: AccessRequestScopeV1 {
                    kind: "organization".to_owned(),
                    id: "org_1".to_owned(),
                    display_name: Some("Acme".to_owned()),
                },
                expires_at: Some(now + chrono::Duration::hours(1)),
            },
            idempotency_key: "access-request:ar_1:submitted".to_owned(),
            correlation_id: "corr_1".to_owned(),
            causation_id: None,
            requested_by: Some("subject_1".to_owned()),
        }
    }

    fn rendered_template(
        template_id: &str,
        requested_locale: &str,
        resolved_locale: &str,
    ) -> RenderedTemplate {
        let subject = "Subject".to_owned();
        let text = "Text".to_owned();
        let html = "<p>Text</p>".to_owned();
        RenderedTemplate {
            template_id: template_id.to_owned(),
            template_version: "v1".to_owned(),
            requested_locale: requested_locale.to_owned(),
            resolved_locale: resolved_locale.to_owned(),
            fallback_used: requested_locale != resolved_locale,
            renderer_identity: "lenso.notification-template.renderer/safe-sections@1".to_owned(),
            template_digest: format!("sha256:{}", "a".repeat(64)),
            content_digest: content_digest(&subject, &text, &html),
            subject,
            text,
            html,
        }
    }
}
