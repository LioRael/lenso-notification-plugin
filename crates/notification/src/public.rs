//! Private intent storage used behind the generated Transactional Capability.

use crate::domain::DeliveryStatus;
use crate::error::{ErrorCode, NotificationError, NotificationResult};
use crate::snapshot::{
    SnapshotProtector, content_digest, mask_email, redact_preview, request_digest,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};

pub const ORGANIZATION_INVITATION_TEMPLATE_ID: &str = "organization-invitation";
pub const ORGANIZATION_INVITATION_TEMPLATE_VERSION: &str = "v1";
pub const ORGANIZATION_INVITATION_RENDERER: &str =
    "lenso.notification.renderer/organization-invitation@v1";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionalIntentReceipt {
    pub intent_id: String,
    pub delivery_id: String,
    pub status: DeliveryStatus,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderedInvitation {
    subject: String,
    text: String,
    html: String,
}

/// Persists one idempotent intent inside a Notification-owned transaction.
pub(crate) async fn create_transactional_email_intent_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    request: &CreateTransactionalEmailIntent,
    now: DateTime<Utc>,
    protector: &dyn SnapshotProtector,
) -> NotificationResult<TransactionalIntentReceipt> {
    validate_request(request, now)?;
    let digest = request_digest(request)?;

    // Serialize contenders before checking the business idempotency record so
    // same-key requests cannot race into two snapshots.
    sqlx::query("select pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "notification:{}:{}",
            request.source.module_id, request.idempotency_key
        ))
        .execute(tx.as_mut())
        .await
        .map_err(map_sql_error)?;

    if let Some(existing) = find_idempotent_intent(tx, request, &digest).await? {
        return Ok(existing);
    }

    let rendered = render_organization_invitation(&request.template, &request.recipient.locale);
    let message_digest = content_digest(&rendered.subject, &rendered.text, &rendered.html);
    let template_digest = template_digest(&request.recipient.locale);
    let template_release_id = stable_id(
        "ntf_tpl",
        &format!(
            "{ORGANIZATION_INVITATION_TEMPLATE_ID}:{ORGANIZATION_INVITATION_TEMPLATE_VERSION}:{}",
            request.recipient.locale
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
    .bind(ORGANIZATION_INVITATION_TEMPLATE_ID)
    .bind(ORGANIZATION_INVITATION_TEMPLATE_VERSION)
    .bind(&request.recipient.locale)
    .bind(ORGANIZATION_INVITATION_RENDERER)
    .bind(&template_digest)
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
    .bind(ORGANIZATION_INVITATION_TEMPLATE_ID)
    .bind(ORGANIZATION_INVITATION_TEMPLATE_VERSION)
    .bind(&request.recipient.locale)
    .fetch_one(tx.as_mut())
    .await
    .map_err(map_sql_error)?;
    if stored_template_digest != template_digest {
        return Err(NotificationError::new(
            ErrorCode::Conflict,
            "Notification template release is immutable",
        ));
    }

    let subject = protector.protect(&rendered.subject)?;
    let text = protector.protect(&rendered.text)?;
    let html = protector.protect(&rendered.html)?;
    if subject.key_reference != text.key_reference || text.key_reference != html.key_reference {
        return Err(NotificationError::new(
            ErrorCode::Internal,
            "Notification snapshot protection key changed during rendering",
        ));
    }
    let recipient = protector.protect(&request.recipient.address)?;
    let snapshot_id = stable_id("ntf_snp", &digest);
    let intent_id = stable_id(
        "ntf_int",
        &format!(
            "{}:{}:{}",
            request.source.module_id, request.idempotency_key, digest
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
    .bind(redact_preview(&rendered.text))
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
            $1, 'transactional.organization_invitation', $2, $3, $4,
            $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
        )
        "#,
    )
    .bind(&intent_id)
    .bind(&request.source.module_id)
    .bind(&request.source.entity_type)
    .bind(&request.source.entity_id)
    .bind(&recipient.ciphertext)
    .bind(&recipient.key_reference)
    .bind(mask_email(&request.recipient.address))
    .bind(&request.recipient.locale)
    .bind(&snapshot_id)
    .bind(&request.idempotency_key)
    .bind(&digest)
    .bind(&request.requested_by)
    .bind(&request.correlation_id)
    .bind(&request.causation_id)
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
    request: &CreateTransactionalEmailIntent,
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
    .bind(&request.source.module_id)
    .bind(&request.idempotency_key)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(map_sql_error)?;
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

fn validate_request(
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

fn render_organization_invitation(
    template: &OrganizationInvitationTemplateV1,
    locale: &str,
) -> RenderedInvitation {
    let organization = template.organization_name.trim();
    let inviter = template
        .inviter_display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let role = template
        .role_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let introduction = inviter.map_or_else(
        || format!("You have been invited to join {organization}."),
        |name| format!("{name} invited you to join {organization}."),
    );
    let role_line = role.map_or_else(String::new, |value| format!("\nRole: {value}"));
    let expiry = template.expires_at.to_rfc3339();
    let text = format!(
        "{introduction}{role_line}\n\nAccept invitation: {}\nExpires: {expiry}\n\nIf you did not expect this invitation, you can ignore this email.",
        template.invitation_url
    );
    let subject = format!("Invitation to join {organization}");
    let html = format!(
        "<!doctype html><html lang=\"{}\"><body><p>{}</p>{}<p><a href=\"{}\">Accept invitation</a></p><p>Expires: {}</p><p>If you did not expect this invitation, you can ignore this email.</p></body></html>",
        escape_html(locale),
        escape_html(&introduction),
        role.map_or_else(String::new, |value| format!(
            "<p>Role: {}</p>",
            escape_html(value)
        )),
        escape_html(&template.invitation_url),
        escape_html(&expiry),
    );
    RenderedInvitation {
        subject,
        text,
        html,
    }
}

fn template_digest(locale: &str) -> String {
    let definition = format!(
        "{ORGANIZATION_INVITATION_RENDERER}\0{locale}\0subject:introduction:role:invitation_url:expires_at"
    );
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(definition.as_bytes()))
    )
}

fn stable_id(prefix: &str, input: &str) -> String {
    let digest = hex::encode(Sha256::digest(input.as_bytes()));
    format!("{prefix}_{}", &digest[..32])
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn map_sql_error(error: sqlx::Error) -> NotificationError {
    NotificationError::new(ErrorCode::Internal, "Notification storage operation failed")
        .with_source(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_renderer_is_deterministic_and_escapes_html() {
        let template = OrganizationInvitationTemplateV1 {
            organization_id: "org_1".to_owned(),
            organization_name: "Acme <Ops>".to_owned(),
            invitation_id: "inv_1".to_owned(),
            invitation_url: "https://example.test/i?a=1&token=secret".to_owned(),
            inviter_display_name: Some("Alice & Bob".to_owned()),
            role_name: Some("Admin".to_owned()),
            expires_at: DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
        };
        let first = render_organization_invitation(&template, "en");
        let second = render_organization_invitation(&template, "en");
        assert_eq!(first, second);
        assert!(first.html.contains("Acme &lt;Ops&gt;"));
        assert!(first.html.contains("&amp;token=secret"));
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
            validate_request(&request, now)
                .expect_err("campaign rejected")
                .code,
            ErrorCode::Validation
        );
    }
}
